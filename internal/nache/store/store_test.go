package store

import (
	"context"
	"errors"
	"testing"

	capabilityv1 "dariyanws/gen/dariya/capability/v1"
)

func capFor(account string) *capabilityv1.Capability {
	return &capabilityv1.Capability{AccountId: account}
}

const (
	acctA = "000000000001"
	acctB = "000000000002"
)

func TestCreateIsIdempotentAndPerAccount(t *testing.T) {
	s := OpenTest(t, "store")
	ctx := context.Background()

	c, created, err := s.Create(ctx, capFor(acctA), "c1")
	if err != nil || !created || c.Account() != acctA || c.State != Creating {
		t.Fatalf("Create = %+v %v %v", c, created, err)
	}
	if _, created, err := s.Create(ctx, capFor(acctA), "c1"); err != nil || created {
		t.Fatalf("second Create: created=%v err=%v", created, err)
	}
	// The same name in another account is another cluster.
	if c, created, err := s.Create(ctx, capFor(acctB), "c1"); err != nil || !created || c.Account() != acctB {
		t.Fatalf("B's Create = %+v %v %v", c, created, err)
	}

	if got, _ := s.List(ctx, capFor(acctA)); len(got) != 1 {
		t.Fatalf("A lists %d clusters", len(got))
	}
	if _, err := s.Get(ctx, capFor(acctB), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing = %v", err)
	}
	if n, _ := s.Count(ctx, capFor(acctA)); n != 1 {
		t.Fatalf("Count = %d", n)
	}
	if all, _ := s.All(ctx); len(all) != 2 {
		t.Fatalf("All = %d", len(all))
	}
}

func TestACapabilityWithNoAccountCreatesNothing(t *testing.T) {
	s := OpenTest(t, "store")
	if _, _, err := s.Create(context.Background(), &capabilityv1.Capability{}, "c1"); err == nil {
		t.Fatal("a cluster was created for no account")
	}
}

// The race SetObserved's WHERE clause exists for: a reconciler pass reads a creating cluster, the
// customer deletes it, and the pass writes back "active". The delete must win.
func TestAReconcilerPassCannotResurrectADeletedCluster(t *testing.T) {
	s := OpenTest(t, "store")
	ctx := context.Background()

	c, _, err := s.Create(ctx, capFor(acctA), "c1")
	if err != nil {
		t.Fatal(err)
	}
	stale := c // what the pass read

	if _, err := s.MarkDeleting(ctx, capFor(acctA), "c1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetObserved(ctx, stale, []Node{{ID: "n", Status: "available"}}, true); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, capFor(acctA), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != Deleting {
		t.Fatalf("state = %s after a stale pass, want deleting", got.State)
	}
}

func TestANameIsNotFreeUntilItsClusterIsGone(t *testing.T) {
	s := OpenTest(t, "store")
	ctx := context.Background()

	c, _, _ := s.Create(ctx, capFor(acctA), "c1")
	if _, err := s.MarkDeleting(ctx, capFor(acctA), "c1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create(ctx, capFor(acctA), "c1"); !errors.Is(err, ErrDeleting) {
		t.Fatalf("Create while deleting = %v, want ErrDeleting", err)
	}

	if err := s.Forget(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, created, err := s.Create(ctx, capFor(acctA), "c1"); err != nil || !created {
		t.Fatalf("Create after Forget: created=%v err=%v", created, err)
	}
}

func TestForgetRemovesOnlyDeletingClusters(t *testing.T) {
	s := OpenTest(t, "store")
	ctx := context.Background()

	c, _, _ := s.Create(ctx, capFor(acctA), "keep")
	if err := s.Forget(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, capFor(acctA), "keep"); err != nil {
		t.Fatalf("Forget removed a cluster nobody deleted: %v", err)
	}
}

func TestObservedNodesRoundTrip(t *testing.T) {
	s := OpenTest(t, "store")
	ctx := context.Background()

	c, _, _ := s.Create(ctx, capFor(acctA), "c1")
	if err := s.SetObserved(ctx, c, []Node{{ID: "n-0", Status: "available"}}, true); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, capFor(acctA), "c1")
	if got.State != Active || len(got.Nodes) != 1 || got.Nodes[0].ID != "n-0" {
		t.Fatalf("after SetObserved: %+v", got)
	}
}
