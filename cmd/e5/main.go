// Command e5 is BREAK.md E5's harness: what a crash, or a death, costs a managed cache.
//
//	e5 orphan      nache dies between "chala started the node" and "the row recorded it"
//	e5 nodedeath   the node is SIGKILLed while nache runs normally
//
// It assumes the region is up with chala and the front door running (see README), the engine
// image built, and dev + nache credentials exported. It starts and stops nache itself, because in
// the orphan run nache's death is the thing under test.
//
// Three numbers per run, on the clocks they belong to:
//
//  1. the system's: from the fault until the cluster's record says it is whole again — host clock,
//     because the host both injects the fault and polls Describe;
//  2. the client's: the gap a client looping PING on the customer network actually saw — the
//     daemon's clock, from its timestamps on the probe's output, so the interval is measured on one
//     clock even if the host's and Docker Desktop's VM disagree;
//  3. the most instances ever tagged for the cluster at once. Anything above one is a duplicate,
//     and the claim fails however good the other two numbers are.
//
// Fidelity gaps, stated: the probe is started by hand with `docker run` on the customer's network,
// as an operator would, because chala has no exec and a client instance cannot report back yet;
// and the orphan fault is os.Exit inside nache at exactly the worst instant (--e5-crash-after-run),
// not a SIGKILL from outside at a random one.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"dariyanws/internal/chala/docker"
	"dariyanws/internal/signing"
)

const (
	frontDoor = "http://127.0.0.1:8080"
	region    = "hind-1"
	sample    = 50 * time.Millisecond
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "orphan" && os.Args[1] != "nodedeath") {
		fmt.Fprintln(os.Stderr, "usage: e5 orphan|nodedeath")
		os.Exit(2)
	}
	for _, v := range []string{"DARIYA_ACCOUNT_ID", "DARIYA_ACCESS_KEY_ID", "DARIYA_SECRET_ACCESS_KEY",
		"NACHE_ACCESS_KEY_ID", "NACHE_SECRET_ACCESS_KEY", "NACHE_ACCOUNT_ID"} {
		if os.Getenv(v) == "" {
			fail("%s is not set — export the dev token and the nache service account first", v)
		}
	}

	h := &harness{
		account: os.Getenv("DARIYA_ACCOUNT_ID"),
		svc:     os.Getenv("NACHE_ACCOUNT_ID"),
		cred: signing.Credentials{AccessKeyID: os.Getenv("DARIYA_ACCESS_KEY_ID"),
			Secret: []byte(os.Getenv("DARIYA_SECRET_ACCESS_KEY"))},
		docker: docker.New(docker.DefaultSocket()),
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	h.cluster = "e5-" + hex.EncodeToString(b)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	defer h.cleanup()

	switch os.Args[1] {
	case "orphan":
		h.orphan(ctx)
	case "nodedeath":
		h.nodeDeath(ctx)
	}
}

type harness struct {
	account, svc, cluster string
	cred                  signing.Credentials
	docker                *docker.Client

	nache *exec.Cmd
	probe string

	mu        sync.Mutex
	maxNodes  int
	stateLog  []string
	lastState string
}

// ---------------------------------------------------------------------------
// The two runs
// ---------------------------------------------------------------------------

func (h *harness) orphan(ctx context.Context) {
	h.startProbe(ctx)
	go h.sampleNodes(ctx)

	h.startNache("--e5-crash-after-run")
	h.call("PUT", "")
	if err := h.nache.Wait(); err == nil {
		fail("nache exited cleanly; the crash hook did not fire")
	}
	killed := time.Now()
	h.note("nache died between RunNode and the row update")

	// Restarted at once, as a supervisor would. The restart's own cost is part of the number,
	// and is reported separately so it can be subtracted.
	h.startNache()
	h.waitHealthy(ctx)
	restarted := time.Now()

	h.waitFor(ctx, func(state, node string) bool {
		return state == "RESOURCE_STATE_ACTIVE" && node == "CACHE_NODE_STATUS_AVAILABLE"
	})
	adopted := time.Now()
	time.Sleep(2 * time.Second) // let the probe log a steady tail

	h.report("orphan", map[string]time.Duration{
		"nache down (kill → healthy again)": restarted.Sub(killed),
		"system: kill → cluster ACTIVE":     adopted.Sub(killed),
		"system: nache restart → ACTIVE":    adopted.Sub(restarted),
	})
}

func (h *harness) nodeDeath(ctx context.Context) {
	h.startNache()
	h.waitHealthy(ctx)
	h.startProbe(ctx)
	go h.sampleNodes(ctx)

	h.call("PUT", "")
	h.waitFor(ctx, func(state, node string) bool {
		return state == "RESOURCE_STATE_ACTIVE" && node == "CACHE_NODE_STATUS_AVAILABLE"
	})
	time.Sleep(3 * time.Second) // a steady run of successes before the fault

	node := "chala-" + h.svc + "-n-" + h.account + "-" + h.cluster
	before, err := h.docker.InspectContainer(ctx, node)
	if err != nil {
		fail("inspect node: %v", err)
	}
	if err := h.docker.Kill(ctx, before.ID); err != nil {
		fail("kill node: %v", err)
	}
	killed := time.Now()
	h.note("node SIGKILLed")

	h.waitFor(ctx, func(state, nodeStatus string) bool {
		if nodeStatus != "CACHE_NODE_STATUS_AVAILABLE" {
			return false
		}
		after, err := h.docker.InspectContainer(ctx, node)
		return err == nil && after.ID != before.ID
	})
	recovered := time.Now()
	time.Sleep(2 * time.Second)

	h.report("nodedeath", map[string]time.Duration{
		"system: kill → replacement AVAILABLE": recovered.Sub(killed),
	})
}

// ---------------------------------------------------------------------------
// Instruments
// ---------------------------------------------------------------------------

// startProbe runs a client on the customer's network that tries a real RESP PING every 50ms and
// prints ok or fail. The daemon timestamps each line.
func (h *harness) startProbe(ctx context.Context) {
	ep := fmt.Sprintf("%s.%s.nache.dariya.internal", h.cluster, h.account)
	script := fmt.Sprintf(`while :; do
  if printf '*1\r\n$4\r\nPING\r\n' | nc -w 1 %s 6379 2>/dev/null | grep -q PONG; then echo ok; else echo fail; fi
  sleep 0.05
done`, ep)
	id, err := h.docker.CreateContainer(ctx, "e5-probe-"+h.cluster, docker.ContainerSpec{
		Image: "busybox:1.36", Cmd: []string{"sh", "-c", script},
		Network: "dariya-acct-" + h.account, Labels: map[string]string{"dariya.e5": h.cluster},
	})
	if err != nil {
		fail("probe: %v (has the account network been created? run any instance once)", err)
	}
	if err := h.docker.StartContainer(ctx, id); err != nil {
		fail("probe: %v", err)
	}
	h.probe = id
}

// sampleNodes records the most instances ever tagged for this cluster at once.
func (h *harness) sampleNodes(ctx context.Context) {
	filter := []string{"dariya.tag.cluster=" + h.cluster, "dariya.tag.cluster-account=" + h.account}
	for ctx.Err() == nil {
		ids, err := h.docker.ListContainers(ctx, filter)
		if err == nil {
			running := 0
			for _, id := range ids {
				if c, err := h.docker.InspectContainer(ctx, id); err == nil && c.Status != "exited" && c.Status != "dead" {
					running++
				}
			}
			h.mu.Lock()
			if running > h.maxNodes {
				h.maxNodes = running
			}
			h.mu.Unlock()
		}
		time.Sleep(sample)
	}
}

// waitFor polls Describe until done says so, logging every change of state it sees.
func (h *harness) waitFor(ctx context.Context, done func(state, node string) bool) {
	for ctx.Err() == nil {
		status, body := h.call("GET", "")
		if status == http.StatusOK {
			var resp struct {
				Cluster struct {
					State string
					Nodes []struct{ Status string }
				}
			}
			_ = json.Unmarshal(body, &resp)
			node := ""
			if len(resp.Cluster.Nodes) > 0 {
				node = resp.Cluster.Nodes[0].Status
			}
			h.observe(resp.Cluster.State + " / " + node)
			if done(resp.Cluster.State, node) {
				return
			}
		}
		time.Sleep(sample)
	}
	fail("timed out waiting for the cluster")
}

func (h *harness) observe(s string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s != h.lastState {
		h.lastState = s
		h.stateLog = append(h.stateLog, time.Now().Format("15:04:05.000")+"  "+s)
	}
}

func (h *harness) note(s string) { h.observe("— " + s) }

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

func (h *harness) report(run string, system map[string]time.Duration) {
	lines, err := h.docker.Logs(context.Background(), h.probe)
	if err != nil {
		fail("probe logs: %v", err)
	}

	// Client numbers, all on the daemon's clock.
	var firstOK, gapStart, gapEnd time.Time
	var worstGap time.Duration
	fails, failsAfterFirstOK := 0, 0
	var lastOK time.Time
	for _, l := range lines {
		switch l.Text {
		case "ok":
			if firstOK.IsZero() {
				firstOK = l.Time
			}
			if !lastOK.IsZero() {
				if gap := l.Time.Sub(lastOK); gap > worstGap {
					worstGap, gapStart, gapEnd = gap, lastOK, l.Time
				}
			}
			lastOK = l.Time
		case "fail":
			fails++
			if !firstOK.IsZero() {
				failsAfterFirstOK++
			}
		}
	}

	fmt.Printf("E5 %s — cluster %s\n\n", run, h.cluster)
	fmt.Println("observed (host clock):")
	for _, s := range h.stateLog {
		fmt.Println("  " + s)
	}
	fmt.Println("\nsystem (host clock):")
	keys := make([]string, 0, len(system))
	for k := range system {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-40s %s\n", k, system[k].Round(time.Millisecond))
	}
	fmt.Println("\nclient (daemon clock, one PING attempt per ~50ms):")
	fmt.Printf("  attempts %d, failed %d, failed after the first success %d\n", len(lines), fails, failsAfterFirstOK)
	if !firstOK.IsZero() {
		fmt.Printf("  first success at probe start + %s\n", firstOK.Sub(lines[0].Time).Round(time.Millisecond))
	}
	fmt.Printf("  longest gap between successes %s", worstGap.Round(time.Millisecond))
	if !gapStart.IsZero() {
		fmt.Printf("  (%s → %s)", gapStart.Format("15:04:05.000"), gapEnd.Format("15:04:05.000"))
	}
	fmt.Println()
	h.mu.Lock()
	fmt.Printf("\nmost instances tagged for the cluster at once: %d  %s\n", h.maxNodes,
		map[bool]string{true: "(claim holds)", false: "(DUPLICATE — the claim fails)"}[h.maxNodes <= 1])
	h.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

func (h *harness) startNache(extra ...string) {
	if h.nache != nil && h.nache.ProcessState == nil {
		_ = h.nache.Process.Kill()
		_ = h.nache.Wait()
	}
	log, _ := os.OpenFile("/tmp/e5-nache.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	h.nache = exec.Command("./bin/nache", append([]string{"--dev"}, extra...)...)
	h.nache.Stdout, h.nache.Stderr = log, log
	if err := h.nache.Start(); err != nil {
		fail("start nache: %v", err)
	}
}

func (h *harness) waitHealthy(ctx context.Context) {
	for ctx.Err() == nil {
		if resp, err := http.Get("http://127.0.0.1:8083/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	fail("nache never became healthy")
}

// call signs a request as the dev account against this run's cluster.
func (h *harness) call(method, body string) (int, []byte) {
	path := "/nache/2026-09-30/clusters/" + h.cluster
	auth, headers := signing.Sign(signing.Request{Method: method, Path: path, Body: []byte(body)},
		h.cred, region, "nache", time.Now())
	req, _ := http.NewRequest(method, frontDoor+path, strings.NewReader(body))
	req.Header.Set("Authorization", auth)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (h *harness) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if h.probe != "" {
		_ = h.docker.RemoveContainer(ctx, h.probe)
	}
	h.call("DELETE", "")
	if h.nache != nil && h.nache.ProcessState == nil {
		// Give the reconciler a few passes to take the node down before stopping it.
		time.Sleep(5 * time.Second)
		_ = h.nache.Process.Signal(os.Interrupt)
		_ = h.nache.Wait()
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "e5: "+format+"\n", args...)
	os.Exit(1)
}
