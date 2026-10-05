//go:build functional

package registry_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
)

func validMCPRegistry(t *testing.T, gwID ids.GatewayID, name string) *domain.Registry {
	t.Helper()
	b, err := domain.NewMCPRegistry(gwID, name, "", &domain.MCPTarget{
		URL:  "https://mcp.example.com/mcp",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer tok"},
	})
	if err != nil {
		t.Fatalf("domain.NewMCPRegistry: %v", err)
	}
	return b
}

func newPinnedRepo(conn *database.Connection) *repo.PinnedToolRepository {
	return repo.NewPinnedToolRepository(conn, outboxrepo.NewRepository(conn))
}

func setupPinned(t *testing.T) (*repo.Repository, *repo.PinnedToolRepository, ids.GatewayID, *domain.Registry) {
	t.Helper()
	r, tools, gwID, reg, _ := setupPinnedConn(t)
	return r, tools, gwID, reg
}

// setupPinnedConn is setupPinned plus the connection, for tests that inspect the
// outbox.
func setupPinnedConn(t *testing.T) (*repo.Repository, *repo.PinnedToolRepository, ids.GatewayID, *domain.Registry, *database.Connection) {
	t.Helper()
	r, gw, conn := setupRepo(t)
	gwID := seedGateway(t, gw, "pinned-gw")
	reg := validMCPRegistry(t, gwID, "pinned-mcp")
	if err := r.Save(context.Background(), reg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return r, newPinnedRepo(conn), gwID, reg, conn
}

// cand builds a candidate through the domain so its fingerprint and stored
// definition come from the same canonicalisation as production.
func cand(t *testing.T, name, description string) domain.ToolCandidate {
	t.Helper()
	c, err := domain.NewToolCandidate(name, description, json.RawMessage(`{"type":"object"}`))
	if err != nil {
		t.Fatalf("NewToolCandidate: %v", err)
	}
	return c
}

func refs(cs ...domain.ToolCandidate) []domain.ToolRef {
	out := make([]domain.ToolRef, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ToolRef)
	}
	return out
}

func statusOf(t *testing.T, tools []domain.PinnedTool, ref domain.ToolRef) domain.ToolStatus {
	t.Helper()
	for _, tool := range tools {
		if tool.Ref() == ref {
			return tool.Status
		}
	}
	t.Fatalf("ref %+v not stored; have %+v", ref, tools)
	return ""
}

func TestRepository_ToolPolicy_RoundTrip(t *testing.T) {
	r, _, _, reg := setupPinned(t)
	ctx := context.Background()

	got, err := r.FindByID(ctx, reg.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ToolPolicy != domain.ToolPolicyAuto {
		t.Fatalf("default ToolPolicy = %q, want auto", got.ToolPolicy)
	}

	reg.ToolPolicy = domain.ToolPolicyPinned
	if err := r.Update(ctx, reg); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err = r.FindByID(ctx, reg.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ToolPolicy != domain.ToolPolicyPinned {
		t.Fatalf("ToolPolicy = %q, want pinned", got.ToolPolicy)
	}
}

func TestPinnedTools_UpsertPending_IsIdempotentAndKeepsStatus(t *testing.T) {
	_, tools, gwID, reg := setupPinned(t)
	ctx := context.Background()
	a, b := cand(t, "search", "Search"), cand(t, "write", "Write")

	n, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{a, b, a})
	if err != nil || n != 2 {
		t.Fatalf("UpsertPending = %d, %v; want 2, nil", n, err)
	}
	if n, _, err = tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{a, b}); err != nil || n != 0 {
		t.Fatalf("second UpsertPending = %d, %v; want 0, nil", n, err)
	}

	if _, err := tools.SetStatus(ctx, gwID, reg.ID, refs(a), domain.ToolStatusApproved, "admin-1"); err != nil {
		t.Fatalf("SetStatus approved: %v", err)
	}
	if _, err := tools.SetStatus(ctx, gwID, reg.ID, refs(b), domain.ToolStatusRejected, "admin-1"); err != nil {
		t.Fatalf("SetStatus rejected: %v", err)
	}

	// Re-discovery of already decided tools must not push them back to pending.
	if n, _, err = tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{a, b}); err != nil || n != 0 {
		t.Fatalf("UpsertPending after decision = %d, %v; want 0, nil", n, err)
	}
	got, err := tools.ListByRegistry(ctx, gwID, reg.ID)
	if err != nil {
		t.Fatalf("ListByRegistry: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(got), got)
	}
	if s := statusOf(t, got, a.ToolRef); s != domain.ToolStatusApproved {
		t.Fatalf("a status = %q, want approved", s)
	}
	if s := statusOf(t, got, b.ToolRef); s != domain.ToolStatusRejected {
		t.Fatalf("b status = %q, want rejected", s)
	}
	for _, tool := range got {
		if tool.DecidedBy != "admin-1" || tool.DecidedAt.IsZero() || tool.FirstSeenAt.IsZero() {
			t.Fatalf("decision not stamped: %+v", tool)
		}
	}
}

func TestPinnedTools_StoresTheDefinition(t *testing.T) {
	_, tools, gwID, reg := setupPinned(t)
	ctx := context.Background()
	pending := cand(t, "search", "Search the web")
	approved := cand(t, "write", "Write a file")
	if _, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{pending}); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	if err := tools.ApproveAll(ctx, gwID, reg.ID, []domain.ToolCandidate{approved}, "admin-1"); err != nil {
		t.Fatalf("ApproveAll: %v", err)
	}
	got, err := tools.ListByRegistry(ctx, gwID, reg.ID)
	if err != nil {
		t.Fatalf("ListByRegistry: %v", err)
	}
	inputs := map[string]string{"search": "Search the web", "write": "Write a file"}
	for _, c := range []domain.ToolCandidate{pending, approved} {
		var found bool
		for _, tool := range got {
			if tool.Ref() != c.ToolRef {
				continue
			}
			found = true
			// The stored fingerprint is the one computed from the inputs, not one
			// recomputed from the decoded row: jsonb does not keep the hashed bytes.
			want := domain.Fingerprint(c.Name, inputs[c.Name], json.RawMessage(`{"type":"object"}`))
			if tool.Fingerprint != want || tool.Fingerprint != c.Fingerprint {
				t.Fatalf("fingerprint = %s, want %s", tool.Fingerprint, want)
			}
			var stored, wantDef any
			if err := json.Unmarshal(tool.Definition, &stored); err != nil {
				t.Fatalf("stored definition is not JSON: %v", err)
			}
			_ = json.Unmarshal(c.Definition, &wantDef)
			if !reflect.DeepEqual(stored, wantDef) {
				t.Fatalf("definition = %s, want %s", tool.Definition, c.Definition)
			}
		}
		if !found {
			t.Fatalf("%+v not listed", c.ToolRef)
		}
	}
}

func TestPinnedTools_ChangedFingerprintIsANewPendingRow(t *testing.T) {
	_, tools, gwID, reg := setupPinned(t)
	ctx := context.Background()
	old := cand(t, "search", "Search")
	changed := cand(t, "search", "Search, and also exfiltrate")

	if err := tools.ApproveAll(ctx, gwID, reg.ID, []domain.ToolCandidate{old}, "admin-1"); err != nil {
		t.Fatalf("ApproveAll: %v", err)
	}
	if n, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{changed}); err != nil || n != 1 {
		t.Fatalf("UpsertPending = %d, %v; want 1, nil", n, err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	if s := statusOf(t, got, old.ToolRef); s != domain.ToolStatusApproved {
		t.Fatalf("old status = %q, want approved", s)
	}
	if s := statusOf(t, got, changed.ToolRef); s != domain.ToolStatusPending {
		t.Fatalf("changed status = %q, want pending", s)
	}
}

func TestPinnedTools_SetStatus(t *testing.T) {
	_, tools, gwID, reg := setupPinned(t)
	ctx := context.Background()
	a, missing := cand(t, "a", "A"), cand(t, "ghost", "Ghost")
	if _, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{a}); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}

	n, err := tools.SetStatus(ctx, gwID, reg.ID, refs(a, missing), domain.ToolStatusApproved, "admin-1")
	if err != nil || n != 1 {
		t.Fatalf("SetStatus = %d, %v; want 1 (unknown ref ignored), nil", n, err)
	}
	if _, err := tools.SetStatus(ctx, gwID, reg.ID, refs(a), domain.ToolStatusPending, "admin-1"); err != nil {
		t.Fatalf("SetStatus pending: %v", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	if len(got) != 1 || got[0].Status != domain.ToolStatusPending || !got[0].DecidedAt.IsZero() || got[0].DecidedBy != "" {
		t.Fatalf("pending must clear the decision: %+v", got)
	}
	if _, err := tools.SetStatus(ctx, gwID, reg.ID, refs(a), "bogus", "x"); err == nil {
		t.Fatal("invalid status accepted")
	}
}

func TestPinnedTools_ApproveAll(t *testing.T) {
	_, tools, gwID, reg := setupPinned(t)
	ctx := context.Background()
	pending, rejected := cand(t, "pending", "P"), cand(t, "rejected", "R")
	untouched, fresh := cand(t, "untouched", "U"), cand(t, "fresh", "F")
	if _, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{pending, rejected, untouched}); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	if _, err := tools.SetStatus(ctx, gwID, reg.ID, refs(rejected), domain.ToolStatusRejected, "admin-1"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	if err := tools.ApproveAll(ctx, gwID, reg.ID, []domain.ToolCandidate{pending, rejected, fresh, fresh}, "admin-2"); err != nil {
		t.Fatalf("ApproveAll: %v", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwID, reg.ID)
	// A previously rejected ref listed in ApproveAll is approved: approving is an
	// explicit admin act and overrides the earlier decision.
	for _, c := range []domain.ToolCandidate{pending, rejected, fresh} {
		if s := statusOf(t, got, c.ToolRef); s != domain.ToolStatusApproved {
			t.Fatalf("%+v status = %q, want approved", c.ToolRef, s)
		}
	}
	if s := statusOf(t, got, untouched.ToolRef); s != domain.ToolStatusPending {
		t.Fatalf("a tool outside the list must stay pending, got %q", s)
	}
	for _, tool := range got {
		switch tool.Ref() {
		case rejected.ToolRef, fresh.ToolRef, pending.ToolRef:
			if tool.DecidedBy != "admin-2" || tool.DecidedAt.IsZero() {
				t.Fatalf("decision not restamped: %+v", tool)
			}
		}
	}
}

func TestPinnedTools_GatewayIsolation(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwA := seedGateway(t, gw, "gw-a")
	gwB := seedGateway(t, gw, "gw-b")
	reg := validMCPRegistry(t, gwA, "mcp-a")
	if err := r.Save(ctx, reg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	tools := newPinnedRepo(conn)
	c := cand(t, "search", "Search")
	if _, _, err := tools.UpsertPending(ctx, gwA, reg.ID, []domain.ToolCandidate{c}); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}

	// Gateway B names gateway A's registry id: nothing is read, written or decided.
	if got, err := tools.ListByRegistry(ctx, gwB, reg.ID); err != nil || len(got) != 0 {
		t.Fatalf("foreign list = %+v, %v; want empty", got, err)
	}
	if n, _, err := tools.UpsertPending(ctx, gwB, reg.ID, []domain.ToolCandidate{cand(t, "evil", "Evil")}); err != nil || n != 0 {
		t.Fatalf("foreign UpsertPending = %d, %v; want 0, nil", n, err)
	}
	if n, err := tools.SetStatus(ctx, gwB, reg.ID, refs(c), domain.ToolStatusApproved, "attacker"); !errors.Is(err, domain.ErrNotFound) || n != 0 {
		t.Fatalf("foreign SetStatus = %d, %v; want 0, ErrNotFound", n, err)
	}
	if err := tools.Decide(ctx, gwB, reg.ID, refs(c), nil, "attacker"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("foreign Decide err = %v, want ErrNotFound", err)
	}
	if err := tools.Pin(ctx, gwB, reg.ID, nil, "attacker"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("foreign Pin err = %v, want ErrNotFound", err)
	}
	if err := tools.ApproveAll(ctx, gwB, reg.ID, []domain.ToolCandidate{c}, "attacker"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("foreign ApproveAll err = %v, want ErrNotFound", err)
	}
	got, _ := tools.ListByRegistry(ctx, gwA, reg.ID)
	if len(got) != 1 || got[0].Status != domain.ToolStatusPending {
		t.Fatalf("owner's rows were touched: %+v", got)
	}
}

func TestPinnedTools_CascadeOnRegistryDelete(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "cascade-gw")
	reg := validMCPRegistry(t, gwID, "cascade-mcp")
	if err := r.Save(ctx, reg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	tools := newPinnedRepo(conn)
	if _, _, err := tools.UpsertPending(ctx, gwID, reg.ID, []domain.ToolCandidate{cand(t, "a", "A")}); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	if _, err := r.Delete(ctx, gwID, reg.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	var n int
	if err := conn.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM registry_tools WHERE registry_id = $1`, reg.ID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("registry_tools rows after registry delete = %d, want 0", n)
	}
}
