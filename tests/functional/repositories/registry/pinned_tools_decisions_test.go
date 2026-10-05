//go:build functional

package registry_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
	if _, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{a, b}); err != nil {
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
	if _, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{a}); err != nil {
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

func pendingCount(t *testing.T, tools interface {
	ListByRegistry(context.Context, ids.GatewayID, ids.RegistryID) ([]domain.PinnedTool, error)
}, gw ids.GatewayID, reg ids.RegistryID) int {
	t.Helper()
	got, err := tools.ListByRegistry(context.Background(), gw, reg)
	if err != nil {
		t.Fatalf("ListByRegistry: %v", err)
	}
	n := 0
	for _, r := range got {
		if r.Status == domain.ToolStatusPending {
			n++
		}
	}
	return n
}

func TestPinnedTools_UpsertPending_CapsVariantsPerToolName(t *testing.T) {
	_, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	var variants []domain.ToolCandidate
	for i := 0; i < domain.MaxPendingPerToolName+5; i++ {
		variants = append(variants, cand(t, "shape-shifter", "variant "+string(rune('a'+i))))
	}
	in, dropped, err := tools.UpsertPending(ctx, gwID, reg.ID, variants)
	if err != nil || in != domain.MaxPendingPerToolName || dropped != 5 {
		t.Fatalf("UpsertPending = %d inserted, %d dropped, %v; want %d, 5", in, dropped, err, domain.MaxPendingPerToolName)
	}
	// Offering them again drops the same five and stores nothing new.
	in, dropped, _ = tools.UpsertPending(ctx, gwID, reg.ID, variants)
	if in != 0 || dropped != 5 {
		t.Fatalf("second call = %d, %d; want 0, 5", in, dropped)
	}
	// Another name is unaffected.
	if in, _, _ := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{cand(t, "other", "o")}); in != 1 {
		t.Fatalf("a different name must still be accepted, inserted %d", in)
	}
}

func TestPinnedTools_UpsertPending_CapsRegistryAndDecisionsFreeRoom(t *testing.T) {
	_, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	name := func(i int) string {
		return "tool-" + string(rune('A'+i/26/26%26)) + string(rune('A'+i/26%26)) + string(rune('A'+i%26))
	}
	var all []domain.ToolCandidate
	for i := 0; i < domain.MaxPendingPerRegistry+10; i++ {
		all = append(all, cand(t, name(i), "d"))
	}
	in, dropped, err := tools.UpsertPending(ctx, gwID, reg.ID, all)
	if err != nil || in != domain.MaxPendingPerRegistry || dropped != 10 {
		t.Fatalf("UpsertPending = %d, %d, %v; want %d, 10", in, dropped, err, domain.MaxPendingPerRegistry)
	}
	stored, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	// Deciding some rows frees room: only pending rows count.
	if err := tools.Decide(ctx, gwID, reg.ID, refs(all[0], all[1], all[2]), nil, "admin"); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	var notStored []domain.ToolCandidate
	have := map[domain.ToolRef]bool{}
	for _, s := range stored {
		have[s.Ref()] = true
	}
	for _, c := range all {
		if !have[c.ToolRef] {
			notStored = append(notStored, c)
		}
	}
	in, dropped, _ = tools.UpsertPending(ctx, gwID, reg.ID, notStored)
	if in != 3 || dropped != 7 {
		t.Fatalf("after deciding 3 rows: %d inserted, %d dropped; want 3, 7", in, dropped)
	}
}

// Concurrent recorders of one registry must never overshoot the cap: the check
// and the insert are serialised by the registry row lock.
func TestPinnedTools_UpsertPending_CapHoldsUnderConcurrency(t *testing.T) {
	_, tools, gwID, reg, _ := setupPinnedConn(t)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			var batch []domain.ToolCandidate
			for i := 0; i < 100; i++ {
				batch = append(batch, cand(t, fmt.Sprintf("w%d-t%03d", w, i), "d"))
			}
			if _, _, err := tools.UpsertPending(context.Background(), gwID, reg.ID, batch); err != nil {
				t.Errorf("UpsertPending: %v", err)
			}
		}(w)
	}
	wg.Wait()
	if n := pendingCount(t, tools, gwID, reg.ID); n != domain.MaxPendingPerRegistry {
		t.Fatalf("pending rows = %d, want exactly %d", n, domain.MaxPendingPerRegistry)
	}
}

// "Enable pinning" can commit between an update's read and its write. The update
// does not mention the policy, so it must leave the stored one alone: writing the
// stale "auto" back would turn pinning off, which fails open.
func TestRepository_Update_WithoutAPolicyDoesNotRevertAConcurrentPin(t *testing.T) {
	r, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()

	loaded, err := r.FindByID(ctx, reg.ID) // the updater's read: policy is auto
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if err := tools.Pin(ctx, gwID, reg.ID, nil, "admin"); err != nil { // lands in between
		t.Fatalf("Pin: %v", err)
	}

	loaded.Description = "edited"
	loaded.KeepStoredToolPolicy = true // what the updater sets when the request has no tool_policy
	loaded.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, loaded); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if loaded.ToolPolicy != domain.ToolPolicyPinned {
		t.Fatalf("Update must hand back the stored policy, got %q", loaded.ToolPolicy)
	}
	got, _ := r.FindByID(ctx, reg.ID)
	if got.ToolPolicy != domain.ToolPolicyPinned || got.Description != "edited" {
		t.Fatalf("policy=%q description=%q; want pinned/edited", got.ToolPolicy, got.Description)
	}

	// A request that does set the policy still wins.
	got.ToolPolicy = domain.ToolPolicyAuto
	got.KeepStoredToolPolicy = false
	got.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if again, _ := r.FindByID(ctx, reg.ID); again.ToolPolicy != domain.ToolPolicyAuto {
		t.Fatalf("an explicit policy change was ignored: %q", again.ToolPolicy)
	}
}
