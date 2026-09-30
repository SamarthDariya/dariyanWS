package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// These run against the real daemon and skip without one, as the store tests do without Postgres.
// A fake daemon would test that this package agrees with the author's reading of the API docs,
// which is the thing most likely to be wrong.

const testImage = "busybox:1.36"

func daemon(t *testing.T) (*Client, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	c := New(DefaultSocket())
	if err := c.Ping(ctx); err != nil {
		t.Skipf("no Docker daemon (%v) — `open -a Docker` to run these", err)
	}
	if ok, err := c.ImageExists(ctx, testImage); err != nil {
		t.Fatalf("ImageExists: %v", err)
	} else if !ok {
		if err := c.PullImage(ctx, testImage); err != nil {
			t.Fatalf("PullImage: %v", err)
		}
	}
	return c, ctx
}

// scratch labels every object a test creates, and removes them all afterwards.
func scratch(t *testing.T, c *Client) (string, map[string]string) {
	t.Helper()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	labels := map[string]string{"dariya.test": id}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ids, _ := c.ListContainers(ctx, []string{"dariya.test=" + id})
		for _, cid := range ids {
			_ = c.RemoveContainer(ctx, cid)
		}
		for _, n := range []string{"dtest-a-" + id, "dtest-b-" + id} {
			_, _ = c.do(ctx, "DELETE", "/networks/"+n, nil, nil, nil)
		}
	})
	return id, labels
}

func run(t *testing.T, c *Client, ctx context.Context, name string, spec ContainerSpec) string {
	t.Helper()
	id, err := c.CreateContainer(ctx, name, spec)
	if err != nil {
		t.Fatalf("CreateContainer %s: %v", name, err)
	}
	if err := c.StartContainer(ctx, id); err != nil {
		t.Fatalf("StartContainer %s: %v", name, err)
	}
	return id
}

// waitExit polls until the container has exited and returns its exit code.
func waitExit(t *testing.T, c *Client, ctx context.Context, id string) int {
	t.Helper()
	for {
		got, err := c.InspectContainer(ctx, id)
		if err != nil {
			t.Fatalf("InspectContainer: %v", err)
		}
		if got.Status == "exited" || got.Status == "dead" {
			return got.ExitCode
		}
		select {
		case <-ctx.Done():
			t.Fatalf("container %s never exited (status %s)", id, got.Status)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func TestContainerLifecycle(t *testing.T) {
	c, ctx := daemon(t)
	id, labels := scratch(t, c)

	net := "dtest-a-" + id
	if err := c.EnsureNetwork(ctx, NetworkSpec{Name: net, Labels: labels, Internal: true}); err != nil {
		t.Fatalf("EnsureNetwork: %v", err)
	}
	// Twice, because EnsureNetwork is called on every RunInstance.
	if err := c.EnsureNetwork(ctx, NetworkSpec{Name: net, Labels: labels, Internal: true}); err != nil {
		t.Fatalf("EnsureNetwork again: %v", err)
	}

	spec := ContainerSpec{
		Image: testImage, Cmd: []string{"sleep", "300"}, Labels: labels,
		Network: net, Aliases: []string{"web." + id + ".test.internal"},
		MemoryBytes: 64 << 20, PidsLimit: 64,
	}
	name := "dtest-web-" + id
	cid := run(t, c, ctx, name, spec)

	got, err := c.InspectContainer(ctx, name)
	if err != nil {
		t.Fatalf("InspectContainer: %v", err)
	}
	if got.ID != cid || got.Name != name || got.Status != "running" {
		t.Fatalf("inspect = %+v", got)
	}
	if got.Labels["dariya.test"] != id {
		t.Fatalf("labels = %v", got.Labels)
	}
	if got.Networks[net] == "" {
		t.Fatalf("no address on %s: %v", net, got.Networks)
	}

	// The name is the lock.
	if _, err := c.CreateContainer(ctx, name, spec); !errors.Is(err, ErrConflict) {
		t.Fatalf("second create with the same name: err = %v, want ErrConflict", err)
	}

	ids, err := c.ListContainers(ctx, []string{"dariya.test=" + id})
	if err != nil || len(ids) != 1 || ids[0] != cid {
		t.Fatalf("ListContainers = %v, %v", ids, err)
	}

	if err := c.RemoveContainer(ctx, cid); err != nil {
		t.Fatalf("RemoveContainer: %v", err)
	}
	if err := c.RemoveContainer(ctx, cid); err != nil {
		t.Fatalf("removing twice must not be an error: %v", err)
	}
	if _, err := c.InspectContainer(ctx, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("inspect after remove: err = %v, want ErrNotFound", err)
	}
}

// Decisions 13d and 13h, at the lowest level they can be checked: a DNS alias resolves on its own
// network, and a container on a different network cannot even resolve the name, let alone reach
// the address behind it.
func TestAliasResolvesOnItsNetworkAndNowhereElse(t *testing.T) {
	c, ctx := daemon(t)
	id, labels := scratch(t, c)

	netA, netB := "dtest-a-"+id, "dtest-b-"+id
	for _, n := range []string{netA, netB} {
		if err := c.EnsureNetwork(ctx, NetworkSpec{Name: n, Labels: labels, Internal: true}); err != nil {
			t.Fatalf("EnsureNetwork %s: %v", n, err)
		}
	}

	alias := "web." + id + ".test.internal"
	run(t, c, ctx, "dtest-web-"+id, ContainerSpec{
		Image: testImage, Cmd: []string{"sleep", "300"}, Labels: labels,
		Network: netA, Aliases: []string{alias},
	})

	probe := func(name, net string) int {
		cid := run(t, c, ctx, name, ContainerSpec{
			Image: testImage, Cmd: []string{"nslookup", alias}, Labels: labels, Network: net,
		})
		return waitExit(t, c, ctx, cid)
	}

	if code := probe("dtest-same-"+id, netA); code != 0 {
		t.Errorf("the alias did not resolve on its own network (nslookup exit %d)", code)
	}
	if code := probe("dtest-other-"+id, netB); code == 0 {
		t.Errorf("the alias resolved from another network — the networks are not isolated")
	}
}

// Not resolving a name is not the same as not being reachable: a tenant who learned an address
// some other way would not need DNS. This checks the packets, by IP, on a real TCP port.
func TestAnotherNetworkCannotReachTheAddress(t *testing.T) {
	c, ctx := daemon(t)
	id, labels := scratch(t, c)

	netA, netB := "dtest-a-"+id, "dtest-b-"+id
	for _, n := range []string{netA, netB} {
		if err := c.EnsureNetwork(ctx, NetworkSpec{Name: n, Labels: labels, Internal: true}); err != nil {
			t.Fatalf("EnsureNetwork %s: %v", n, err)
		}
	}

	web := run(t, c, ctx, "dtest-web-"+id, ContainerSpec{
		Image: testImage, Cmd: []string{"httpd", "-f", "-p", "8080"}, Labels: labels, Network: netA,
	})
	got, err := c.InspectContainer(ctx, web)
	if err != nil {
		t.Fatalf("InspectContainer: %v", err)
	}
	ip := got.Networks[netA]

	probe := func(name, net string) int {
		cid := run(t, c, ctx, name, ContainerSpec{
			Image: testImage, Cmd: []string{"nc", "-z", "-w", "2", ip, "8080"}, Labels: labels, Network: net,
		})
		return waitExit(t, c, ctx, cid)
	}

	if code := probe("dtest-same-"+id, netA); code != 0 {
		t.Fatalf("could not reach %s:8080 from its own network (exit %d) — the control is broken", ip, code)
	}
	if code := probe("dtest-other-"+id, netB); code == 0 {
		t.Errorf("reached %s:8080 from another network — the networks are not isolated", ip)
	}
}
