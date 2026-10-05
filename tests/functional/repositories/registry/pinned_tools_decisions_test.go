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

	if err := tools.Pin(ctx, gwID, reg.ID, []domain.ToolCandidate{a}, nil, "admin-1"); err != nil {
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
	if err := tools.Pin(context.Background(), gwID, reg.ID, nil, nil, "admin-1"); err != nil {
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

	err := tools.Pin(ctx, gwID, llm.ID, []domain.ToolCandidate{cand(t, "a", "A")}, nil, "admin-1")
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

	if err := tools.Pin(ctx, gwID, reg.ID, []domain.ToolCandidate{good, broken}, nil, "admin-1"); err == nil {
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
	if err := tools.Pin(ctx, gwID, reg.ID, nil, nil, "admin"); err != nil { // lands in between
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

// Pin makes the confirmed list exact: an approved tool left off the list is
// withdrawn, a rejection that is not listed stays, a listed rejection is lifted.
func TestPinnedTools_Pin_MakesTheListExact(t *testing.T) {
	_, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	keep, drop, rej, lift := cand(t, "keep", "K"), cand(t, "drop", "D"), cand(t, "rej", "R"), cand(t, "lift", "L")
	if err := tools.ApproveAll(ctx, gwID, reg.ID, []domain.ToolCandidate{keep, drop}, "admin-1"); err != nil {
		t.Fatalf("ApproveAll: %v", err)
	}
	if _, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{rej, lift}); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	if err := tools.Decide(ctx, gwID, reg.ID, nil, refs(rej, lift), "admin-1"); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	if err := tools.Pin(ctx, gwID, reg.ID, []domain.ToolCandidate{keep, lift}, nil, "admin-2"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	for ref, want := range map[domain.ToolRef]domain.ToolStatus{
		keep.ToolRef: domain.ToolStatusApproved,
		lift.ToolRef: domain.ToolStatusApproved,
		drop.ToolRef: domain.ToolStatusPending,
		rej.ToolRef:  domain.ToolStatusRejected,
	} {
		if s := statusOf(t, got, ref); s != want {
			t.Errorf("%+v = %q, want %q", ref, s, want)
		}
	}
	for _, row := range got {
		if row.Ref() == drop.ToolRef && (!row.DecidedAt.IsZero() || row.DecidedBy != "") {
			t.Errorf("a withdrawn approval must lose its decision: %+v", row)
		}
	}
}

// pinned -> auto -> pinned with a tool unchecked in between: the unchecked tool
// must not come back exposed. The decided set is what the snapshot carries.
func TestPinnedTools_Pin_UncheckedToolIsNotExposedAfterRepin(t *testing.T) {
	r, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	a, b := cand(t, "a", "A"), cand(t, "b", "B")
	if err := tools.Pin(ctx, gwID, reg.ID, []domain.ToolCandidate{a, b}, nil, "admin"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	loaded, _ := r.FindByID(ctx, reg.ID)
	loaded.ToolPolicy = domain.ToolPolicyAuto
	loaded.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, loaded); err != nil {
		t.Fatalf("disable: %v", err)
	}

	if err := tools.Pin(ctx, gwID, reg.ID, []domain.ToolCandidate{a}, nil, "admin"); err != nil { // b unchecked
		t.Fatalf("re-Pin: %v", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	decided := domain.DecisionsOf(got)
	if len(decided) != 1 || decided[0].Name != "a" {
		t.Fatalf("decided set = %+v, want only a (b must be pending again)", decided)
	}
}

func TestPinnedTools_Pin_EmptyListWithdrawsEveryApproval(t *testing.T) {
	_, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	a := cand(t, "a", "A")
	if err := tools.Pin(ctx, gwID, reg.ID, []domain.ToolCandidate{a}, nil, "admin"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if err := tools.Pin(ctx, gwID, reg.ID, nil, nil, "admin"); err != nil {
		t.Fatalf("Pin(empty): %v", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	if len(domain.DecisionsOf(got)) != 0 {
		t.Fatalf("an empty confirmed list must leave nothing approved: %+v", got)
	}
}

// Q2: deciding on a registry that is still auto is allowed (pre-staging) and does
// not switch it to pinned.
func TestPinnedTools_Decide_OnAnAutoRegistryIsAllowedAndKeepsItAuto(t *testing.T) {
	r, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	if policy, _ := registryState(t, r, reg.ID); policy != domain.ToolPolicyAuto {
		t.Fatalf("precondition: policy = %q", policy)
	}
	a := cand(t, "a", "A")
	if _, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{a}); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	if err := tools.Decide(ctx, gwID, reg.ID, refs(a), nil, "admin"); err != nil {
		t.Fatalf("Decide on an auto registry: %v", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	if s := statusOf(t, got, a.ToolRef); s != domain.ToolStatusApproved {
		t.Fatalf("status = %q, want approved", s)
	}
	if policy, _ := registryState(t, r, reg.ID); policy != domain.ToolPolicyAuto {
		t.Fatalf("a decision must not change the policy, got %q", policy)
	}
}

func TestPinnedTools_ListPage_IsStableFilteredAndScoped(t *testing.T) {
	_, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	var all []domain.ToolCandidate
	for i := 0; i < 7; i++ {
		all = append(all, cand(t, fmt.Sprintf("t%d", i), "d"))
	}
	if _, _, err := tools.UpsertPending(ctx, gwID, reg.ID, all); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	if err := tools.Decide(ctx, gwID, reg.ID, refs(all[0], all[1]), nil, "admin"); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	var seen []string
	for offset := 0; ; offset += 3 {
		page, total, err := tools.ListPage(ctx, gwID, reg.ID, nil, 3, offset)
		if err != nil || total != 7 {
			t.Fatalf("ListPage(offset %d) = %d items, total %d, %v", offset, len(page), total, err)
		}
		if len(page) == 0 {
			break
		}
		for _, p := range page {
			seen = append(seen, p.Name)
		}
	}
	if len(seen) != 7 {
		t.Fatalf("pages covered %d rows, want 7 with no repeats: %v", len(seen), seen)
	}
	dup := map[string]bool{}
	for _, n := range seen {
		if dup[n] {
			t.Fatalf("row %s appeared on two pages", n)
		}
		dup[n] = true
	}

	pending := domain.ToolStatusPending
	page, total, _ := tools.ListPage(ctx, gwID, reg.ID, &pending, 100, 0)
	if total != 5 || len(page) != 5 {
		t.Fatalf("pending filter = %d items, total %d; want 5/5", len(page), total)
	}
	approved, err := tools.ListApproved(ctx, gwID, reg.ID, []string{"t0", "t5"})
	if err != nil || len(approved) != 1 || approved[0].Name != "t0" {
		t.Fatalf("ListApproved = %+v, %v; want only t0", approved, err)
	}

	otherGW := ids.New[ids.GatewayKind]()
	if page, total, _ := tools.ListPage(ctx, otherGW, reg.ID, nil, 100, 0); len(page) != 0 || total != 0 {
		t.Fatalf("another gateway read %d rows", len(page))
	}
}

func rowOf(t *testing.T, rows []domain.PinnedTool, ref domain.ToolRef) domain.PinnedTool {
	t.Helper()
	for _, r := range rows {
		if r.Ref() == ref {
			return r
		}
	}
	t.Fatalf("ref %+v not stored", ref)
	return domain.PinnedTool{}
}

// 3 live tools, 2 confirmed: 2 approved, the third is the admin's explicit
// decline, rejected by the caller, with the policy and the bump in the same
// transaction.
func TestPinnedTools_Pin_RejectsUncheckedLiveToolsInTheSameTransaction(t *testing.T) {
	r, tools, gwID, reg, conn := setupPinnedConn(t)
	ctx := context.Background()
	a, b, c3 := cand(t, "a", "A"), cand(t, "b", "B"), cand(t, "create_branch", "C")
	_, before := registryState(t, r, reg.ID)
	markers := outboxCount(t, conn)

	if err := tools.Pin(ctx, gwID, reg.ID, []domain.ToolCandidate{a, b}, []domain.ToolCandidate{c3}, "ana@acme.io"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	for ref, want := range map[domain.ToolRef]domain.ToolStatus{
		a.ToolRef: domain.ToolStatusApproved, b.ToolRef: domain.ToolStatusApproved, c3.ToolRef: domain.ToolStatusRejected,
	} {
		if s := statusOf(t, got, ref); s != want {
			t.Errorf("%s = %q, want %q", ref.Name, s, want)
		}
	}
	if row := rowOf(t, got, c3.ToolRef); row.DecidedBy != "ana@acme.io" || row.DecidedAt.IsZero() {
		t.Errorf("the decline must be attributed: %+v", row)
	}
	policy, after := registryState(t, r, reg.ID)
	if policy != domain.ToolPolicyPinned || !after.After(before) || outboxCount(t, conn) != markers+1 {
		t.Fatalf("policy=%q bumped=%v markers %d->%d", policy, after.After(before), markers, outboxCount(t, conn))
	}
}

func TestPinnedTools_Pin_UncheckedPendingRowBecomesRejected(t *testing.T) {
	_, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	p := cand(t, "p", "P")
	if _, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{p}); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	if err := tools.Pin(ctx, gwID, reg.ID, nil, []domain.ToolCandidate{p}, "ana"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	if row := rowOf(t, got, p.ToolRef); row.Status != domain.ToolStatusRejected || row.DecidedBy != "ana" {
		t.Fatalf("pending row = %+v, want rejected by ana", row)
	}
}

func TestPinnedTools_Pin_AlreadyRejectedUncheckedToolIsUntouched(t *testing.T) {
	_, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	rej := cand(t, "rej", "R")
	if _, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{rej}); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	if err := tools.Decide(ctx, gwID, reg.ID, nil, refs(rej), "first-admin"); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	before, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	if err := tools.Pin(ctx, gwID, reg.ID, nil, []domain.ToolCandidate{rej}, "second-admin"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	after, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	b, a := rowOf(t, before, rej.ToolRef), rowOf(t, after, rej.ToolRef)
	if a.Status != domain.ToolStatusRejected || a.DecidedBy != "first-admin" || !a.DecidedAt.Equal(b.DecidedAt) {
		t.Fatalf("an already rejected tool was rewritten: before %+v after %+v", b, a)
	}
}

// Approved earlier, absent from the live list and from the request: nobody saw
// it this time, so it goes back to pending rather than being rejected.
func TestPinnedTools_Pin_ApprovedToolMissingFromTheLiveListBecomesPending(t *testing.T) {
	_, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	gone, live := cand(t, "gone", "G"), cand(t, "live", "L")
	if err := tools.ApproveAll(ctx, gwID, reg.ID, []domain.ToolCandidate{gone}, "admin"); err != nil {
		t.Fatalf("ApproveAll: %v", err)
	}
	if err := tools.Pin(ctx, gwID, reg.ID, []domain.ToolCandidate{live}, nil, "admin"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	if s := statusOf(t, got, gone.ToolRef); s != domain.ToolStatusPending {
		t.Fatalf("gone = %q, want pending", s)
	}
}

// Empty confirmed list on an introspectable server: every live tool is declined.
func TestPinnedTools_Pin_EmptyListRejectsEveryLiveTool(t *testing.T) {
	_, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	live := []domain.ToolCandidate{cand(t, "a", "A"), cand(t, "b", "B")}
	if err := tools.Pin(ctx, gwID, reg.ID, nil, live, "ana"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	for _, c := range live {
		if s := statusOf(t, got, c.ToolRef); s != domain.ToolStatusRejected {
			t.Errorf("%s = %q, want rejected", c.Name, s)
		}
	}
	if len(domain.DecisionsOf(got)) != 2 {
		t.Fatalf("decisions = %+v", domain.DecisionsOf(got))
	}
}

// Explicit declines are admin decisions, not discoveries: the pending caps do
// not apply to them.
func TestPinnedTools_Pin_UncheckedRejectionsIgnoreThePendingCaps(t *testing.T) {
	_, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	var variants []domain.ToolCandidate
	for i := 0; i < domain.MaxPendingPerToolName+5; i++ {
		variants = append(variants, cand(t, "shape-shifter", fmt.Sprintf("v%d", i)))
	}
	if err := tools.Pin(ctx, gwID, reg.ID, nil, variants, "admin"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	if len(got) != len(variants) {
		t.Fatalf("stored %d of %d declined definitions", len(got), len(variants))
	}
}

// A failure while rejecting the unchecked tools undoes the approvals and the
// policy switch too: nothing survives.
func TestPinnedTools_Pin_RollbackLeavesNothingBehind(t *testing.T) {
	r, tools, gwID, reg, _ := setupPinnedConn(t)
	ctx := context.Background()
	good := cand(t, "good", "G")
	broken := domain.ToolCandidate{ToolRef: domain.ToolRef{Name: "broken", Fingerprint: "f"}, Definition: []byte(`{not json`)}

	if err := tools.Pin(ctx, gwID, reg.ID, []domain.ToolCandidate{good}, []domain.ToolCandidate{cand(t, "other", "O"), broken}, "admin"); err == nil {
		t.Fatal("an unstorable unchecked definition must fail the pin")
	}
	if got, _ := tools.ListByRegistry(ctx, gwID, reg.ID); len(got) != 0 {
		t.Fatalf("rows survived a failed pin: %+v", got)
	}
	if policy, _ := registryState(t, r, reg.ID); policy != domain.ToolPolicyAuto {
		t.Fatalf("policy = %q after a failed pin", policy)
	}
}
