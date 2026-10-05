//go:build functional

package registry_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
)

func outboxCount(t *testing.T, conn *database.Connection) int {
	t.Helper()
	var n int
	if err := conn.Pool.QueryRow(context.Background(), `SELECT count(*) FROM config_snapshot_outbox`).Scan(&n); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	return n
}

func registryState(t *testing.T, r interface {
	FindByID(context.Context, ids.RegistryID) (*domain.Registry, error)
}, id ids.RegistryID) (domain.ToolPolicy, time.Time) {
	t.Helper()
	got, err := r.FindByID(context.Background(), id)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	return got.ToolPolicy, got.UpdatedAt
}

func TestPinnedTools_Decide_AppliesBothListsAndBumpsTheRegistry(t *testing.T) {
	r, tools, gwID, reg, conn := setupPinnedConn(t)
	ctx := context.Background()
	a, b := cand(t, "a", "A"), cand(t, "b", "B")
	if _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{a, b}); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	_, before := registryState(t, r, reg.ID)
	markers := outboxCount(t, conn)

	if err := tools.Decide(ctx, gwID, reg.ID, refs(a), refs(b), "admin-1"); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	if s := statusOf(t, got, a.ToolRef); s != domain.ToolStatusApproved {
		t.Fatalf("a = %q, want approved", s)
	}
	if s := statusOf(t, got, b.ToolRef); s != domain.ToolStatusRejected {
		t.Fatalf("b = %q, want rejected", s)
	}
	if _, after := registryState(t, r, reg.ID); !after.After(before) {
		t.Fatalf("updated_at did not move: %v -> %v", before, after)
	}
	if n := outboxCount(t, conn); n != markers+1 {
		t.Fatalf("markers = %d, want exactly one more than %d", n, markers)
	}
}

func TestPinnedTools_Decide_UnknownRefAppliesNothing(t *testing.T) {
	r, tools, gwID, reg, conn := setupPinnedConn(t)
	ctx := context.Background()
	a, ghost := cand(t, "a", "A"), cand(t, "ghost", "Ghost")
	if _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{a}); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	_, before := registryState(t, r, reg.ID)
	markers := outboxCount(t, conn)

	err := tools.Decide(ctx, gwID, reg.ID, refs(a), refs(ghost), "admin-1")
	if !errors.Is(err, domain.ErrUnknownToolRefs) {
		t.Fatalf("err = %v, want ErrUnknownToolRefs", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	if s := statusOf(t, got, a.ToolRef); s != domain.ToolStatusPending {
		t.Fatalf("the valid ref was applied (%q) although the call was refused", s)
	}
	if _, after := registryState(t, r, reg.ID); !after.Equal(before) {
		t.Fatal("a refused decision must not bump the registry")
	}
	if n := outboxCount(t, conn); n != markers {
		t.Fatalf("a refused decision appended a marker (%d -> %d)", markers, n)
	}
}

func TestPinnedTools_Pin_ApprovesAndFlipsPolicyTogether(t *testing.T) {
	r, tools, gwID, reg, conn := setupPinnedConn(t)
	ctx := context.Background()
	a := cand(t, "a", "A")
	_, before := registryState(t, r, reg.ID)
	markers := outboxCount(t, conn)

	if err := tools.Pin(ctx, gwID, reg.ID, []domain.ToolCandidate{a}, "admin-1"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	policy, after := registryState(t, r, reg.ID)
	if policy != domain.ToolPolicyPinned || !after.After(before) {
		t.Fatalf("policy=%q updated_at %v -> %v", policy, before, after)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	if s := statusOf(t, got, a.ToolRef); s != domain.ToolStatusApproved {
		t.Fatalf("a = %q, want approved", s)
	}
	if n := outboxCount(t, conn); n != markers+1 {
		t.Fatalf("markers = %d, want %d", n, markers+1)
	}
}

func TestPinnedTools_Pin_EmptyListIsAllowed(t *testing.T) {
	r, tools, gwID, reg, _ := setupPinnedConn(t)
	if err := tools.Pin(context.Background(), gwID, reg.ID, nil, "admin-1"); err != nil {
		t.Fatalf("Pin(empty): %v", err)
	}
	if policy, _ := registryState(t, r, reg.ID); policy != domain.ToolPolicyPinned {
		t.Fatalf("policy = %q, want pinned", policy)
	}
}

func TestPinnedTools_Pin_RefusesLLMRegistry(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "llm-gw")
	llm := validRegistry(t, gwID, "llm")
	if err := r.Save(ctx, llm); err != nil {
		t.Fatalf("Save: %v", err)
	}
	tools := newPinnedRepo(conn)
	markers := outboxCount(t, conn)

	err := tools.Pin(ctx, gwID, llm.ID, []domain.ToolCandidate{cand(t, "a", "A")}, "admin-1")
	if !errors.Is(err, domain.ErrInvalidToolPolicy) {
		t.Fatalf("err = %v, want ErrInvalidToolPolicy", err)
	}
	if policy, _ := registryState(t, r, llm.ID); policy != domain.ToolPolicyAuto {
		t.Fatalf("policy = %q, want auto", policy)
	}
	if got, _ := tools.ListByRegistry(ctx, gwID, llm.ID); len(got) != 0 {
		t.Fatalf("rows were written for a refused pin: %+v", got)
	}
	if n := outboxCount(t, conn); n != markers {
		t.Fatalf("marker appended for a refused pin")
	}
}

// A failure after the approvals were written must undo them and leave the policy
// untouched: a half-applied "enable pinning" would pin a registry with no list.
func TestPinnedTools_Pin_RollsBackOnFailure(t *testing.T) {
	r, tools, gwID, reg, conn := setupPinnedConn(t)
	ctx := context.Background()
	good := cand(t, "good", "G")
	broken := domain.ToolCandidate{ToolRef: domain.ToolRef{Name: "broken", Fingerprint: "f"}, Definition: []byte(`{not json`)}
	markers := outboxCount(t, conn)

	if err := tools.Pin(ctx, gwID, reg.ID, []domain.ToolCandidate{good, broken}, "admin-1"); err == nil {
		t.Fatal("a batch with an unstorable definition must fail")
	}
	if policy, _ := registryState(t, r, reg.ID); policy != domain.ToolPolicyAuto {
		t.Fatalf("policy = %q after a failed pin, want auto", policy)
	}
	if got, _ := tools.ListByRegistry(ctx, gwID, reg.ID); len(got) != 0 {
		t.Fatalf("approvals survived a failed pin: %+v", got)
	}
	if n := outboxCount(t, conn); n != markers {
		t.Fatal("marker survived a failed pin")
	}
}
