//go:build functional

package policy_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// seedWithUnreadable saves three policies on one gateway and corrupts the
// middle one in storage (settings becomes a JSON array, which cannot decode into
// the settings map). It returns the gateway and the ids of the readable pair and
// the corrupt one.
func seedWithUnreadable(t *testing.T) (r policyReads, gwID ids.GatewayID, good []ids.PolicyID, bad ids.PolicyID) {
	t.Helper()
	return seedCorrupting(t, `settings = '[1,2]'::jsonb`)
}

type policyReads interface {
	ListByGateway(context.Context, ids.GatewayID) ([]*domain.Policy, error)
	List(context.Context, domain.ListFilter) ([]*domain.Policy, int, error)
	FindByID(context.Context, ids.PolicyID) (*domain.Policy, error)
	FindByIDs(context.Context, ids.GatewayID, []ids.PolicyID) ([]*domain.Policy, error)
}

func seedCorrupting(t *testing.T, set string) (r policyReads, gwID ids.GatewayID, good []ids.PolicyID, bad ids.PolicyID) {
	t.Helper()
	repo, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID = seedGateway(t, gw, "unreadable-gw")

	var all []*domain.Policy
	for _, name := range []string{"a", "b", "c"} {
		p := validPolicy(t, gwID, "rl-"+name)
		p.Slug = "slug_" + name
		if err := repo.Save(ctx, p); err != nil {
			t.Fatalf("Save %s: %v", name, err)
		}
		all = append(all, p)
	}
	bad = all[1].ID
	if _, err := conn.Pool.Exec(ctx, `UPDATE policies SET `+set+` WHERE id = $1`, bad); err != nil {
		t.Fatalf("corrupt settings: %v", err)
	}
	return repo, gwID, []ids.PolicyID{all[0].ID, all[2].ID}, bad
}

func assertOnlyGood(t *testing.T, got []*domain.Policy, good []ids.PolicyID) {
	t.Helper()
	have := map[ids.PolicyID]bool{}
	for _, p := range got {
		have[p.ID] = true
	}
	if len(got) != len(good) {
		t.Fatalf("expected %d readable policies, got %d", len(good), len(got))
	}
	for _, id := range good {
		if !have[id] {
			t.Fatalf("readable policy %s is missing from %v", id, policyIDs(got))
		}
	}
}

func TestRepository_ListByGatewaySkipsUnreadableRow(t *testing.T) {
	r, gwID, good, _ := seedWithUnreadable(t)
	got, err := r.ListByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("one unreadable row must not fail the list: %v", err)
	}
	assertOnlyGood(t, got, good)
}

func TestRepository_ListSkipsUnreadableRow(t *testing.T) {
	r, gwID, good, _ := seedWithUnreadable(t)
	got, total, err := r.List(context.Background(), domain.ListFilter{GatewayID: gwID})
	if err != nil {
		t.Fatalf("one unreadable row must not fail the list: %v", err)
	}
	assertOnlyGood(t, got, good)
	if total != 3 {
		t.Fatalf("total counts the rows matched, unreadable included: got %d want 3", total)
	}
}

// FindByIDs is a targeted lookup: a missing id would read as "deleted", so an
// unreadable row fails it instead of being skipped.
func TestRepository_FindByIDsFailsOnUnreadableRow(t *testing.T) {
	r, gwID, good, bad := seedWithUnreadable(t)
	if _, err := r.FindByIDs(context.Background(), gwID, append([]ids.PolicyID{bad}, good...)); err == nil {
		t.Fatal("FindByIDs must fail when a requested policy is unreadable")
	}
	if got, err := r.FindByIDs(context.Background(), gwID, good); err != nil || len(got) != len(good) {
		t.Fatalf("FindByIDs of readable policies: %v, %d rows", err, len(got))
	}
}

// stages and mcp_scope decode separately from settings; each must be skippable.
func TestRepository_ListSkipsRowsWithCorruptStagesOrScope(t *testing.T) {
	for name, set := range map[string]string{
		"stages":    `stages = '{"a":1}'::jsonb`,
		"mcp_scope": `mcp_scope = '"x"'::jsonb`,
	} {
		t.Run(name, func(t *testing.T) {
			r, gwID, good, _ := seedCorrupting(t, set)
			got, err := r.ListByGateway(context.Background(), gwID)
			if err != nil {
				t.Fatalf("ListByGateway: %v", err)
			}
			assertOnlyGood(t, got, good)
			got, _, err = r.List(context.Background(), domain.ListFilter{GatewayID: gwID})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			assertOnlyGood(t, got, good)
		})
	}
}

func TestRepository_FindByIDFailsOnUnreadableRow(t *testing.T) {
	r, _, good, bad := seedWithUnreadable(t)
	if _, err := r.FindByID(context.Background(), bad); err == nil {
		t.Fatal("FindByID of the unreadable policy must fail loudly")
	}
	if _, err := r.FindByID(context.Background(), good[0]); err != nil {
		t.Fatalf("FindByID of a readable policy: %v", err)
	}
}

func TestRepository_ListStillFailsOnQueryError(t *testing.T) {
	r, gwID, _, _ := seedWithUnreadable(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.ListByGateway(ctx, gwID); err == nil {
		t.Fatal("a query error must still fail the list")
	}
	if _, _, err := r.List(ctx, domain.ListFilter{GatewayID: gwID}); err == nil {
		t.Fatal("a query error must still fail the list")
	}
}
