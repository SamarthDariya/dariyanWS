package nache

import (
	"context"
	"log/slog"
	"time"

	chalav1 "dariyanws/gen/dariya/chala/v1"
	"dariyanws/internal/nache/store"
)

// Reconciler makes the rows true (DESIGN.md decision 13g).
//
// Level-triggered. Each pass reads every cluster and every node from scratch and closes the
// difference, remembering nothing between passes — so a pass that follows a crash, a restart, a
// node dying or a delete is the same code as any other pass, and there is no event it could have
// missed. What the loop costs is detection latency (up to one period) and a full listing per
// pass, both irrelevant at a laptop's scale.
//
// The work-queue structure the decision promised is Wake: anything may ask for a pass now, and a
// missed wake costs latency, never correctness. E5's second run is a wake on "instance exited".
type Reconciler struct {
	Store   *store.Store
	Compute Compute
	Period  time.Duration
	Log     *slog.Logger
	Now     func() time.Time

	// AfterRunNode, if set, runs after chala has accepted a RunNode and before the observation is
	// written back. It exists for one purpose: BREAK.md E5 kills the process exactly there, the
	// window where the node exists and the row does not know it. Nil in every normal run.
	AfterRunNode func(c *store.Cluster)

	wake chan struct{}
}

// Wake asks for a pass as soon as possible. It never blocks, and wakes that arrive during a pass
// collapse into one more pass.
func (r *Reconciler) Wake() {
	select {
	case r.wakeCh() <- struct{}{}:
	default:
	}
}

func (r *Reconciler) wakeCh() chan struct{} {
	if r.wake == nil {
		r.wake = make(chan struct{}, 1)
	}
	return r.wake
}

// Run passes until ctx is done.
func (r *Reconciler) Run(ctx context.Context) {
	wake := r.wakeCh()
	t := time.NewTicker(r.Period)
	defer t.Stop()
	for {
		if err := r.Pass(ctx); err != nil && ctx.Err() == nil {
			r.Log.Warn("reconcile pass failed; the next one retries", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-wake:
		}
	}
}

// Pass is one comparison of desired with actual, and the actions that close it.
//
// The order of the two reads matters. Clusters are read FIRST, nodes second. A node exists only
// because some earlier pass created it for a row, so if a node's cluster is absent from a listing
// taken before the nodes were, the row really was removed — it is an orphan and is terminated.
// Read the other way round, a cluster created between the two reads would have its brand-new node
// look orphaned. (It cannot happen today — only this loop creates nodes — but the order costs
// nothing and does not depend on that staying true.)
func (r *Reconciler) Pass(ctx context.Context) error {
	clusters, err := r.Store.All(ctx)
	if err != nil {
		return err
	}
	nodes, err := r.Compute.Nodes(ctx)
	if err != nil {
		return err
	}

	type key struct{ account, cluster string }
	byCluster := map[key][]*chalav1.Instance{}
	for _, n := range nodes {
		k := key{n.GetTags()[tagClusterAccount], n.GetTags()[tagCluster]}
		byCluster[k] = append(byCluster[k], n)
	}

	var firstErr error
	for _, c := range clusters {
		k := key{c.Account(), c.Name}
		if err := r.reconcile(ctx, c, byCluster[k]); err != nil {
			r.Log.Warn("could not reconcile", "account", c.Account(), "cluster", c.Name, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
		delete(byCluster, k)
	}

	// What is left belongs to no cluster.
	for k, orphans := range byCluster {
		for _, n := range orphans {
			r.Log.Info("terminating orphan", "node", n.GetName(), "account", k.account, "cluster", k.cluster)
			if err := r.Compute.Terminate(ctx, n.GetName()); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// reconcile closes the gap for one cluster.
func (r *Reconciler) reconcile(ctx context.Context, c *store.Cluster, nodes []*chalav1.Instance) error {
	want := NodeName(c.Account(), c.Name)

	if c.State == store.Deleting {
		for _, n := range nodes {
			if err := r.Compute.Terminate(ctx, n.GetName()); err != nil {
				return err
			}
		}
		// Only once every node is confirmed gone. Forgetting first would free the name while the
		// old node still answers at its alias, and a new cluster of the same name would inherit it.
		return r.Store.Forget(ctx, c)
	}

	// Anything tagged for this cluster that is not its node — cannot arise from this code, and is
	// removed rather than trusted if it ever does, because two nodes on one alias is a split.
	var node *chalav1.Instance
	for _, n := range nodes {
		if n.GetName() == want {
			node = n
			continue
		}
		if err := r.Compute.Terminate(ctx, n.GetName()); err != nil {
			return err
		}
	}

	status := nodeCreating
	switch {
	case node == nil:
		// Missing: never created, or terminated by the previous pass for being dead.
		if _, err := r.Compute.RunNode(ctx, c); err != nil {
			return err
		}
		if r.AfterRunNode != nil {
			r.AfterRunNode(c)
		}

	case node.GetState() == chalav1.InstanceState_INSTANCE_STATE_PENDING:
		// A RunInstance that died half way. The same PUT finishes it.
		if _, err := r.Compute.RunNode(ctx, c); err != nil {
			return err
		}

	case node.GetState() == chalav1.InstanceState_INSTANCE_STATE_STOPPED,
		node.GetHealth() == chalav1.InstanceHealth_INSTANCE_HEALTH_UNHEALTHY:
		// Dead or not answering. Replacement is terminate-THEN-start (decision 13h): this pass
		// removes it, the next one creates the replacement under the same name and alias. A
		// short outage rather than two nodes answering one name, which for a cache with no
		// replication is the right way round.
		r.Log.Info("replacing node", "node", want, "state", node.GetState(), "health", node.GetHealth())
		if err := r.Compute.Terminate(ctx, want); err != nil {
			return err
		}
		status = nodeImpaired

	case node.GetHealth() == chalav1.InstanceHealth_INSTANCE_HEALTH_HEALTHY:
		status = nodeAvailable
	}

	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	// Active once, active thereafter: a cluster whose node is being replaced is an ACTIVE cluster
	// with an IMPAIRED node, not a cluster that has gone back to being created.
	return r.Store.SetObserved(ctx, c,
		[]store.Node{{ID: want, Status: status, ObservedAt: now()}},
		status == nodeAvailable)
}
