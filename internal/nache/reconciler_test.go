package nache

import (
	"context"
	"errors"
	"sync"
	"testing"

	capabilityv1 "dariyanws/gen/dariya/capability/v1"
	chalav1 "dariyanws/gen/dariya/chala/v1"
	"dariyanws/internal/nache/store"
)

// fakeCompute behaves like chala as far as the reconciler can tell: RunNode is an idempotent PUT
// by name, Terminate of a missing node is fine. Tests reach in to kill, sicken or heal a node.
type fakeCompute struct {
	mu       sync.Mutex
	nodes    map[string]*chalav1.Instance
	attached map[string]string // node → account it was attached to
	runs     int
	failList error
}

func newFake() *fakeCompute {
	return &fakeCompute{nodes: map[string]*chalav1.Instance{}, attached: map[string]string{}}
}

func (f *fakeCompute) Nodes(context.Context) ([]*chalav1.Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList != nil {
		return nil, f.failList
	}
	var out []*chalav1.Instance
	for _, n := range f.nodes {
		out = append(out, n)
	}
	return out, nil
}

func (f *fakeCompute) RunNode(_ context.Context, c *store.Cluster) (*chalav1.Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs++
	name := NodeName(c.Account(), c.Name)
	n, ok := f.nodes[name]
	if !ok {
		n = &chalav1.Instance{Name: name, Tags: map[string]string{
			tagManagedBy: Service, tagClusterAccount: c.Account(), tagCluster: c.Name}}
		f.nodes[name] = n
	}
	n.State = chalav1.InstanceState_INSTANCE_STATE_RUNNING
	n.Health = chalav1.InstanceHealth_INSTANCE_HEALTH_STARTING
	f.attached[name] = c.Account()
	return n, nil
}

func (f *fakeCompute) Terminate(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.nodes, name)
	return nil
}

func (f *fakeCompute) set(name string, state chalav1.InstanceState, health chalav1.InstanceHealth) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[name].State, f.nodes[name].Health = state, health
}

func (f *fakeCompute) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.nodes)
}

func reconcilerFor(t *testing.T) (*Reconciler, *store.Store, *fakeCompute) {
	t.Helper()
	st := store.OpenTest(t, "reconciler")
	f := newFake()
	return &Reconciler{Store: st, Compute: f, Log: discardLog()}, st, f
}

func mustPass(t *testing.T, r *Reconciler) {
	t.Helper()
	if err := r.Pass(context.Background()); err != nil {
		t.Fatalf("Pass: %v", err)
	}
}

func get(t *testing.T, st *store.Store, account, name string) *store.Cluster {
	t.Helper()
	c, err := st.Get(context.Background(), &capabilityv1.Capability{AccountId: account}, name)
	if err != nil {
		t.Fatalf("Get %s/%s: %v", account, name, err)
	}
	return c
}

func create(t *testing.T, st *store.Store, account, name string) {
	t.Helper()
	if _, _, err := st.Create(context.Background(), &capabilityv1.Capability{AccountId: account}, name); err != nil {
		t.Fatal(err)
	}
}

func TestCreatingBecomesActiveOnceHealthy(t *testing.T) {
	r, st, f := reconcilerFor(t)
	create(t, st, acctA, "c1")
	node := NodeName(acctA, "c1")

	mustPass(t, r)
	if f.count() != 1 || f.attached[node] != acctA {
		t.Fatalf("after pass 1: nodes=%d attached=%v", f.count(), f.attached)
	}
	if c := get(t, st, acctA, "c1"); c.State != store.Creating || c.Nodes[0].Status != nodeCreating {
		t.Fatalf("RUNNING but STARTING must not be active: %+v", c)
	}

	f.set(node, chalav1.InstanceState_INSTANCE_STATE_RUNNING, chalav1.InstanceHealth_INSTANCE_HEALTH_HEALTHY)
	mustPass(t, r)
	if c := get(t, st, acctA, "c1"); c.State != store.Active || c.Nodes[0].Status != nodeAvailable {
		t.Fatalf("HEALTHY must be active: %+v", c)
	}

	// Steady state does nothing.
	runs := f.runs
	mustPass(t, r)
	if f.runs != runs || f.count() != 1 {
		t.Fatalf("a converged cluster was touched: runs %d → %d", runs, f.runs)
	}
}

// Decision 13i's structural rule, observed: every node is attached to its own cluster's account.
func TestEachNodeIsAttachedToItsOwnClustersAccount(t *testing.T) {
	r, st, f := reconcilerFor(t)
	create(t, st, acctA, "same-name")
	create(t, st, acctB, "same-name")

	mustPass(t, r)
	if f.attached[NodeName(acctA, "same-name")] != acctA || f.attached[NodeName(acctB, "same-name")] != acctB {
		t.Fatalf("attachments = %v", f.attached)
	}
}

// The core of E5: nache crashed after chala started the node and before the row recorded it. On
// restart the reconciler sees a row with no observed nodes and a running node tagged for it, and
// adopts it — no second RunInstance, no duplicate.
func TestARestartAdoptsTheNodeItAlreadyStarted(t *testing.T) {
	_, st, f := reconcilerFor(t)
	create(t, st, acctA, "c1")
	node := NodeName(acctA, "c1")

	// The half of a pass that happened before the crash.
	if _, err := f.RunNode(context.Background(), get(t, st, acctA, "c1")); err != nil {
		t.Fatal(err)
	}
	f.set(node, chalav1.InstanceState_INSTANCE_STATE_RUNNING, chalav1.InstanceHealth_INSTANCE_HEALTH_HEALTHY)
	runs := f.runs

	fresh := &Reconciler{Store: st, Compute: f, Log: discardLog()} // a new process: no memory
	mustPass(t, fresh)

	if f.runs != runs || f.count() != 1 {
		t.Fatalf("the restarted reconciler ran another node: runs %d → %d, nodes %d", runs, f.runs, f.count())
	}
	if c := get(t, st, acctA, "c1"); c.State != store.Active {
		t.Fatalf("the adopted node did not make the cluster active: %+v", c)
	}
}

func TestAPendingNodeIsFinished(t *testing.T) {
	r, st, f := reconcilerFor(t)
	create(t, st, acctA, "c1")
	mustPass(t, r)
	node := NodeName(acctA, "c1")
	f.set(node, chalav1.InstanceState_INSTANCE_STATE_PENDING, chalav1.InstanceHealth_INSTANCE_HEALTH_NONE)

	runs := f.runs
	mustPass(t, r)
	if f.runs != runs+1 || f.nodes[node].GetState() != chalav1.InstanceState_INSTANCE_STATE_RUNNING {
		t.Fatalf("PENDING was not finished: runs %d → %d, state %v", runs, f.runs, f.nodes[node].GetState())
	}
}

// Replacement is terminate, then start — in two passes — and the cluster stays ACTIVE throughout.
func TestADeadNodeIsReplacedTerminateFirst(t *testing.T) {
	for name, kill := range map[string]func(*fakeCompute, string){
		"stopped": func(f *fakeCompute, n string) {
			f.set(n, chalav1.InstanceState_INSTANCE_STATE_STOPPED, chalav1.InstanceHealth_INSTANCE_HEALTH_UNHEALTHY)
		},
		"unhealthy": func(f *fakeCompute, n string) {
			f.set(n, chalav1.InstanceState_INSTANCE_STATE_RUNNING, chalav1.InstanceHealth_INSTANCE_HEALTH_UNHEALTHY)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, st, f := reconcilerFor(t)
			create(t, st, acctA, "c1")
			node := NodeName(acctA, "c1")
			mustPass(t, r)
			f.set(node, chalav1.InstanceState_INSTANCE_STATE_RUNNING, chalav1.InstanceHealth_INSTANCE_HEALTH_HEALTHY)
			mustPass(t, r)

			kill(f, node)
			mustPass(t, r)
			if f.count() != 0 {
				t.Fatalf("the dead node was not terminated first")
			}
			c := get(t, st, acctA, "c1")
			if c.State != store.Active || c.Nodes[0].Status != nodeImpaired {
				t.Fatalf("mid-replacement: %+v", c)
			}

			mustPass(t, r)
			if f.count() != 1 {
				t.Fatalf("no replacement was started")
			}
		})
	}
}

func TestDeletingTerminatesThenForgets(t *testing.T) {
	r, st, f := reconcilerFor(t)
	create(t, st, acctA, "c1")
	mustPass(t, r)

	if _, err := st.MarkDeleting(context.Background(), &capabilityv1.Capability{AccountId: acctA}, "c1"); err != nil {
		t.Fatal(err)
	}
	mustPass(t, r)
	if f.count() != 0 {
		t.Fatalf("the node survived its cluster's deletion")
	}
	if _, err := st.Get(context.Background(), &capabilityv1.Capability{AccountId: acctA}, "c1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the row survived: %v", err)
	}
}

func TestAnOrphanIsTerminated(t *testing.T) {
	r, _, f := reconcilerFor(t)
	f.nodes["n-000000000009-ghost"] = &chalav1.Instance{Name: "n-000000000009-ghost",
		State: chalav1.InstanceState_INSTANCE_STATE_RUNNING,
		Tags:  map[string]string{tagManagedBy: Service, tagClusterAccount: "000000000009", tagCluster: "ghost"}}

	mustPass(t, r)
	if f.count() != 0 {
		t.Fatalf("an orphan survived a pass")
	}
}

// If chala cannot be listed, the pass must do nothing at all — above all, it must not conclude
// that every node is missing and start a second set.
func TestAFailedListingChangesNothing(t *testing.T) {
	r, st, f := reconcilerFor(t)
	create(t, st, acctA, "c1")
	mustPass(t, r)
	runs := f.runs

	f.failList = errors.New("chala is down")
	if err := r.Pass(context.Background()); err == nil {
		t.Fatal("a pass with no listing reported success")
	}
	if f.runs != runs {
		t.Fatalf("a pass that could not see the nodes started one")
	}
}
