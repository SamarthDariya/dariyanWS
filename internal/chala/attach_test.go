package chala

import (
	"context"
	"net/http"
	"testing"
	"time"

	chalav1 "dariyanws/gen/dariya/chala/v1"
	"dariyanws/internal/chala/docker"
)

// Decision 13i, from the customer's side: a service account's instance, attached to a customer's
// network under an alias, is reachable by the customer's own instances at that alias — and by no
// other tenant, and is not in the customer's listing.

// listener is a catalog image that answers TCP on 6379, standing in for the cache engine M8 adds.
var listener = Image{
	ID: "img-listen", Description: "test: answers on 6379", Ref: "busybox:1.36",
	Cmd: []string{"nc", "-lk", "-p", "6379", "-e", "echo", "PONG"},
}

func attachHarness(t *testing.T, svcAcct string, accounts ...string) *harness {
	return newHarnessWith(t, Config{
		MaxInstancesPerAccount: 5,
		Catalog:                append(DefaultCatalog(), listener),
		ServiceAccounts:        map[string]string{svcAcct: "nache"},
	}, append(accounts, svcAcct)...)
}

// probe runs `nc -z` against target from a throwaway container on account's network.
func probe(t *testing.T, h *harness, account, target string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := h.docker.EnsureNetwork(ctx, docker.NetworkSpec{Name: NetworkName(account), Internal: true,
		Labels: map[string]string{labelKind: kindNetwork, labelAccount: account}}); err != nil {
		t.Fatal(err)
	}
	id, err := h.docker.CreateContainer(ctx, "probe-"+account+"-"+time.Now().Format("150405.000000"),
		docker.ContainerSpec{
			Image: "busybox:1.36", Cmd: []string{"nc", "-z", "-w", "2", target, "6379"},
			Network: NetworkName(account), Labels: map[string]string{labelAccount: account},
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.docker.StartContainer(ctx, id); err != nil {
		t.Fatal(err)
	}
	for {
		c, err := h.docker.InspectContainer(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if c.Status == "exited" {
			return c.ExitCode
		}
		select {
		case <-ctx.Done():
			t.Fatal("probe never finished")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func TestServiceAccountAttachesToACustomerNetwork(t *testing.T) {
	svc, customer, stranger := testAccount(t), testAccount(t), testAccount(t)
	h := attachHarness(t, svc, customer, stranger)

	alias := "c1." + customer + ".nache.dariya.internal"
	body := map[string]any{
		"imageId": "img-listen", "tags": map[string]string{"cluster": "c1"},
		"attachAccountId": customer, "attachDnsAliases": []string{alias},
	}
	status, inst, raw := h.run(svc, "c1-node-0", body)
	if status != http.StatusOK {
		t.Fatalf("RunInstance = %d: %s", status, raw)
	}
	if inst.GetAccountId() != svc || inst.GetAttachedAccountId() != customer ||
		inst.GetAttachedPrivateIp() == "" || len(inst.GetAttachedDnsAliases()) != 1 {
		t.Fatalf("instance = %v", inst)
	}

	if code := probe(t, h, customer, alias); code != 0 {
		t.Fatalf("the customer could not reach %s (exit %d)", alias, code)
	}
	if code := probe(t, h, stranger, alias); code == 0 {
		t.Fatalf("another tenant reached %s", alias)
	}
	if code := probe(t, h, stranger, inst.GetAttachedPrivateIp()); code == 0 {
		t.Fatalf("another tenant reached %s by address", inst.GetAttachedPrivateIp())
	}

	// Owned by the service: the customer reaches it, and cannot see it.
	if got := h.list(customer, ""); len(got) != 0 {
		t.Fatalf("the customer's listing shows %d instances", len(got))
	}
	if got := h.list(svc, "?tag.cluster=c1"); len(got) != 1 {
		t.Fatalf("the service's listing = %v", got)
	}

	// A retry is the same instance; a retry that attaches elsewhere is a different request.
	if status, _, raw := h.run(svc, "c1-node-0", body); status != http.StatusOK {
		t.Fatalf("retry = %d: %s", status, raw)
	}
	body["attachAccountId"] = stranger
	body["attachDnsAliases"] = []string{"c1." + stranger + ".nache.dariya.internal"}
	if status, _, raw := h.run(svc, "c1-node-0", body); status != http.StatusBadRequest {
		t.Fatalf("re-attach elsewhere under the same name = %d: %s", status, raw)
	}
}

func TestOnlyServiceAccountsMayAttach(t *testing.T) {
	svc, customer, other := testAccount(t), testAccount(t), testAccount(t)
	h := attachHarness(t, svc, customer, other)

	// An ordinary tenant attaching its instance into someone else's network is the attack this
	// whole rule is for.
	status, _, raw := h.run(customer, "sneaky", map[string]any{
		"imageId": "img-shell", "attachAccountId": other,
	})
	if status != http.StatusForbidden {
		t.Fatalf("a tenant attached to another tenant's network: %d %s", status, raw)
	}
	if got := h.list(customer, ""); len(got) != 0 {
		t.Fatalf("the refused request left %d instances behind", len(got))
	}
}

func TestAliasesStayInTheServicesNamespace(t *testing.T) {
	svc, customer, other := testAccount(t), testAccount(t), testAccount(t)
	h := attachHarness(t, svc, customer, other)

	for name, alias := range map[string]string{
		"a chala instance name": "web." + customer + ".chala.dariya.internal",
		"another service":       "c1." + customer + ".kyu.dariya.internal",
		"another customer":      "c1." + other + ".nache.dariya.internal",
		"no label":              "." + customer + ".nache.dariya.internal",
		"nested label":          "a.b." + customer + ".nache.dariya.internal",
		"outside the zone":      "google.com",
	} {
		t.Run(name, func(t *testing.T) {
			status, _, raw := h.run(svc, "n", map[string]any{
				"imageId": "img-listen", "attachAccountId": customer, "attachDnsAliases": []string{alias},
			})
			if status != http.StatusBadRequest {
				t.Fatalf("alias %s = %d: %s", alias, status, raw)
			}
		})
	}

	status, _, raw := h.run(svc, "n", map[string]any{
		"imageId": "img-listen", "attachDnsAliases": []string{"c1." + customer + ".nache.dariya.internal"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("aliases without an attachment = %d: %s", status, raw)
	}
	status, _, raw = h.run(svc, "n", map[string]any{"imageId": "img-listen", "attachAccountId": svc})
	if status != http.StatusBadRequest {
		t.Fatalf("attaching to its own network = %d: %s", status, raw)
	}
}

// A RunInstance that died after create but before the attach leaves an unattached, PENDING
// instance. The retry attaches it and then starts it — never the other way round.
func TestRetryFinishesAnUnattachedInstance(t *testing.T) {
	svc, customer := testAccount(t), testAccount(t)
	h := attachHarness(t, svc, customer)
	ctx := context.Background()

	if err := h.docker.EnsureNetwork(ctx, docker.NetworkSpec{Name: NetworkName(svc), Internal: true,
		Labels: map[string]string{labelKind: kindNetwork, labelAccount: svc}}); err != nil {
		t.Fatal(err)
	}
	alias := "c2." + customer + ".nache.dariya.internal"
	labels := instanceLabels(svc, "c2-node-0", listener.ID, nil)
	labels[labelAttachAccount] = customer
	labels[labelAttachAliases] = alias
	if _, err := h.docker.CreateContainer(ctx, containerName(svc, "c2-node-0"), docker.ContainerSpec{
		Image: listener.Ref, Cmd: listener.Cmd, Network: NetworkName(svc), Labels: labels,
	}); err != nil {
		t.Fatal(err)
	}

	status, inst, raw := h.run(svc, "c2-node-0", map[string]any{
		"imageId": "img-listen", "attachAccountId": customer, "attachDnsAliases": []string{alias},
	})
	if status != http.StatusOK || inst.GetState() != chalav1.InstanceState_INSTANCE_STATE_RUNNING ||
		inst.GetAttachedPrivateIp() == "" {
		t.Fatalf("retry = %d %v: %s", status, inst, raw)
	}
	if code := probe(t, h, customer, alias); code != 0 {
		t.Fatalf("the finished instance is not reachable from the customer (exit %d)", code)
	}
}

func TestServiceAccountsConfigIsChecked(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"chala itself":  {"000000000001": "chala"},
		"short account": {"123": "nache"},
		"bad segment":   {"000000000001": "Nache!"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(nil, nil, Config{Catalog: DefaultCatalog(), ServiceAccounts: m}); err == nil {
				t.Fatalf("%v was accepted", m)
			}
		})
	}
}
