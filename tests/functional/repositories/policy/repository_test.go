//go:build functional

package policy_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	consumerrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/consumer"
	gatewayrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/policy"
	registryrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newRegistryRepo(conn *database.Connection) *registryrepo.Repository {
	cipher, err := crypto.NewCipher("functional-test-secret-0123456789abcdef")
	if err != nil {
		panic(err)
	}
	return registryrepo.NewRepository(conn, cipher, outboxrepo.NewRepository(conn))
}

func setupRepo(t *testing.T) (*repo.Repository, *gatewayrepo.Repository, *database.Connection) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping policy repository integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PG_TEST_URL: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open pgxpool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping: %v", err)
	}

	conn := &database.Connection{Pool: pool}
	manager := database.NewMigrationsManager(pool)
	if err := manager.ApplyPending(ctx); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE consumer_policy, policies, consumers, registries, gateways CASCADE")
		pool.Close()
	})

	appender := outboxrepo.NewRepository(conn)
	return repo.NewRepository(conn, appender), gatewayrepo.NewRepository(conn, appender), conn
}

func seedConsumer(t *testing.T, conn *database.Connection, gwID ids.GatewayID, name string) ids.ConsumerID {
	t.Helper()
	ctx := context.Background()
	reg, err := registrydomain.NewLLMRegistry(gwID, name+"-reg", "", &registrydomain.LLMTarget{
		Provider: "openai",
		Auth:     registrydomain.NewAPIKeyAuth("sk-test"),
	})
	if err != nil {
		t.Fatalf("registry domain.NewLLMRegistry: %v", err)
	}
	if err := newRegistryRepo(conn).Save(ctx, reg); err != nil {
		t.Fatalf("registry Save: %v", err)
	}
	cons, err := consumerdomain.New(consumerdomain.CreateParams{
		GatewayID:   gwID,
		Name:        name,
		Type:        consumerdomain.TypeLLM,
		RegistryIDs: []ids.RegistryID{reg.ID},
	})
	if err != nil {
		t.Fatalf("consumer domain.New: %v", err)
	}
	if err := consumerrepo.NewRepository(conn, outboxrepo.NewRepository(conn)).Save(ctx, cons); err != nil {
		t.Fatalf("consumer Save: %v", err)
	}
	return cons.ID
}

func seedGateway(t *testing.T, gw *gatewayrepo.Repository, name string) ids.GatewayID {
	t.Helper()
	g, err := gatewaydomain.New(name)
	if err != nil {
		t.Fatalf("gateway domain.New: %v", err)
	}
	if err := gw.Save(context.Background(), g); err != nil {
		t.Fatalf("gateway Save: %v", err)
	}
	return g.ID
}

func validPolicy(t *testing.T, gwID ids.GatewayID, name string) *domain.Policy {
	t.Helper()
	p, err := domain.NewPolicy(gwID, name, "rate_limiter", true, 0, false,
		map[string]any{"limit": 100}, []domain.Stage{domain.StagePreRequest}, "round-trip description", domain.ModeEnforce, nil)
	if err != nil {
		t.Fatalf("policy domain.NewPolicy: %v", err)
	}
	return p
}

func scopedPolicy(t *testing.T, gwID ids.GatewayID, name string, scope *domain.MCPScope) *domain.Policy {
	t.Helper()
	p, err := domain.NewPolicy(gwID, name, "trustguard", true, 0, false,
		nil, []domain.Stage{domain.StagePreRequest}, "", domain.ModeEnforce, scope)
	if err != nil {
		t.Fatalf("policy domain.NewPolicy: %v", err)
	}
	return p
}

func seedMCPRegistry(t *testing.T, conn *database.Connection, gwID ids.GatewayID, name string) ids.RegistryID {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(gwID, name, "", &registrydomain.MCPTarget{
		URL: "https://" + name + ".example.com/mcp",
	})
	if err != nil {
		t.Fatalf("registry domain.NewMCPRegistry: %v", err)
	}
	if err := newRegistryRepo(conn).Save(context.Background(), reg); err != nil {
		t.Fatalf("registry Save: %v", err)
	}
	return reg.ID
}

func rawMCPScope(t *testing.T, conn *database.Connection, id ids.PolicyID) (isNull bool, text string) {
	t.Helper()
	if err := conn.Pool.QueryRow(context.Background(),
		"SELECT mcp_scope IS NULL, COALESCE(mcp_scope::text, '') FROM policies WHERE id = $1", id,
	).Scan(&isNull, &text); err != nil {
		t.Fatalf("read raw mcp_scope: %v", err)
	}
	return isNull, text
}

func policyIDs(items []*domain.Policy) []ids.PolicyID {
	out := make([]ids.PolicyID, 0, len(items))
	for _, p := range items {
		out = append(out, p.ID)
	}
	return out
}

func TestRepository_SaveAndFindByID(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw")

	p := validPolicy(t, gwID, "default")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != p.ID || got.GatewayID != gwID || got.Name != "default" {
		t.Fatalf("FindByID returned %+v", got)
	}
	if got.Slug != "rate_limiter" {
		t.Fatalf("Slug round-trip lost data: %+v", got)
	}
	if got.Description != "round-trip description" {
		t.Fatalf("Description round-trip lost data: %+v", got)
	}
	if len(got.Stages) != 1 || got.Stages[0] != domain.StagePreRequest {
		t.Fatalf("Stages round-trip lost data: %+v", got.Stages)
	}
	if got.Mode != domain.ModeEnforce {
		t.Fatalf("Mode round-trip lost data: %+v", got.Mode)
	}
	if got.Settings["limit"] != float64(100) {
		t.Fatalf("Settings round-trip lost data: %+v", got.Settings)
	}
}

func TestRepository_SaveAndFindByID_EmptySettings(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-empty")

	p, err := domain.NewPolicy(gwID, "empty", "rate_limiter", true, 0, false, nil, nil, "", domain.ModeEnforce, nil)
	if err != nil {
		t.Fatalf("domain.NewPolicy: %v", err)
	}
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.Settings) != 0 {
		t.Fatalf("Settings len = %d, want 0", len(got.Settings))
	}
	if len(got.Stages) != 0 {
		t.Fatalf("Stages len = %d, want 0", len(got.Stages))
	}
}

func TestRepository_FindByID_NotFound(t *testing.T) {
	r, _, _ := setupRepo(t)
	_, err := r.FindByID(context.Background(), ids.New[ids.PolicyKind]())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("err = %v, want it to wrap commonerrors.ErrNotFound", err)
	}
}

func TestRepository_Save_DuplicateNameForSameGateway(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-dup")

	p1 := validPolicy(t, gwID, "dupe")
	if err := r.Save(ctx, p1); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	p2 := validPolicy(t, gwID, "dupe")
	err := r.Save(ctx, p2)
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestRepository_Save_InvalidGatewayID(t *testing.T) {
	r, _, _ := setupRepo(t)
	ctx := context.Background()
	orphan := ids.New[ids.GatewayKind]()
	p := validPolicy(t, orphan, "orphan")
	err := r.Save(ctx, p)
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestRepository_Update(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-upd")

	p := validPolicy(t, gwID, "alpha")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	p.Name = "alpha-renamed"
	p.Slug = "rate_limiter"
	p.Enabled = false
	p.Stages = []domain.Stage{domain.StagePostResponse}
	p.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, p, true); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if got.Name != "alpha-renamed" {
		t.Fatalf("Name = %q, want alpha-renamed", got.Name)
	}
	if got.Slug != "rate_limiter" || got.Enabled {
		t.Fatalf("update not persisted: %+v", got)
	}
	if len(got.Stages) != 1 || got.Stages[0] != domain.StagePostResponse {
		t.Fatalf("Stages not persisted: %+v", got.Stages)
	}
}

func TestRepository_Update_NotFound(t *testing.T) {
	r, gw, _ := setupRepo(t)
	gwID := seedGateway(t, gw, "pgw-upd2")
	p := validPolicy(t, gwID, "ghost")
	err := r.Update(context.Background(), p, true)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-del")

	p := validPolicy(t, gwID, "victim")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := r.Delete(ctx, gwID, p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.FindByID(ctx, p.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete_NotFound(t *testing.T) {
	r, _, _ := setupRepo(t)
	err := r.Delete(context.Background(), ids.New[ids.GatewayKind](), ids.New[ids.PolicyKind]())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_List_FilterByGatewayAndName(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, gw, "pgw-l1")
	gw2 := seedGateway(t, gw, "pgw-l2")

	mustSave := func(p *domain.Policy) {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	mustSave(validPolicy(t, gw1, "openai-prod"))
	mustSave(validPolicy(t, gw1, "openai-staging"))
	mustSave(validPolicy(t, gw2, "anthropic-prod"))

	items, total, err := r.List(ctx, domain.ListFilter{GatewayID: gw1, Page: listing.Page{Number: 1, Size: 10}})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("List(gw1) total=%d len=%d, want 2/2", total, len(items))
	}

	items, total, err = r.List(ctx, domain.ListFilter{Search: "anthropic", Page: listing.Page{Number: 1, Size: 10}})
	if err != nil {
		t.Fatalf("List name: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Name != "anthropic-prod" {
		t.Fatalf("List(name) returned %+v", items)
	}

	items, total, err = r.List(ctx, domain.ListFilter{Page: listing.Page{Number: 1, Size: 10}})
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("List all total=%d len=%d, want 3/3", total, len(items))
	}
}

func TestRepository_List_RestrictToSlugs(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-slug")

	mustSave := func(p *domain.Policy) {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	mustSave(validPolicy(t, gwID, "rate-one"))
	p2, err := domain.NewPolicy(gwID, "size-one", "request_size_limiter", true, 0, false,
		map[string]any{"allowed_payload_size": 10, "size_unit": "megabytes"}, []domain.Stage{domain.StagePreRequest}, "", domain.ModeEnforce, nil)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	mustSave(p2)

	items, total, err := r.List(ctx, domain.ListFilter{
		GatewayID:       gwID,
		RestrictToSlugs: true,
		Slugs:           []string{"rate_limiter"},
		Page:            listing.Page{Number: 1, Size: 10},
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Slug != "rate_limiter" {
		t.Fatalf("List(slug) total=%d items=%+v", total, items)
	}

	items, total, err = r.List(ctx, domain.ListFilter{
		GatewayID:       gwID,
		RestrictToSlugs: true,
		Slugs:           []string{},
		Page:            listing.Page{Number: 1, Size: 10},
	})
	if err != nil {
		t.Fatalf("List empty slugs: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("List(empty restrict) total=%d len=%d", total, len(items))
	}
}

func TestRepository_GlobalFlag_RoundTripAndListByGateway(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-global")

	global := validPolicy(t, gwID, "global-pol")
	if err := r.Save(ctx, global); err != nil {
		t.Fatalf("Save global: %v", err)
	}
	if _, err := r.SetGlobal(ctx, gwID, global.ID, true, time.Time{}); err != nil {
		t.Fatalf("SetGlobal: %v", err)
	}

	scoped := validPolicy(t, gwID, "scoped-pol")
	if err := r.Save(ctx, scoped); err != nil {
		t.Fatalf("Save scoped: %v", err)
	}

	got, err := r.FindByID(ctx, global.ID)
	if err != nil {
		t.Fatalf("FindByID global: %v", err)
	}
	if !got.IsGlobal() {
		t.Fatal("policy promoted via SetGlobal should report global")
	}

	all, err := r.ListByGateway(ctx, gwID)
	if err != nil {
		t.Fatalf("ListByGateway: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListByGateway len = %d, want 2", len(all))
	}
	var globals, scopedCount int
	for _, p := range all {
		if p.IsGlobal() {
			globals++
		} else {
			scopedCount++
		}
	}
	if globals != 1 || scopedCount != 1 {
		t.Fatalf("expected 1 global + 1 scoped, got %d/%d", globals, scopedCount)
	}
}

func TestRepository_PlacementSetters_SwapAndDemote(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-placement")

	p := validPolicy(t, gwID, "placement")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	setGlobal := func(on bool) func() (domain.Placement, error) {
		return func() (domain.Placement, error) { return r.SetGlobal(ctx, gwID, p.ID, on, time.Time{}) }
	}
	setMCPWide := func(on bool) func() (domain.Placement, error) {
		return func() (domain.Placement, error) { return r.SetMCPWide(ctx, gwID, p.ID, on, time.Time{}) }
	}
	steps := []struct {
		name        string
		write       func() (domain.Placement, error)
		wantGlobal  bool
		wantMCPWide bool
	}{
		{name: "promote to mcp-wide", write: setMCPWide(true), wantMCPWide: true},
		{name: "swap to global clears mcp-wide", write: setGlobal(true), wantGlobal: true},
		{name: "demoting mcp-wide keeps global", write: setMCPWide(false), wantGlobal: true},
		{name: "swap to mcp-wide clears global", write: setMCPWide(true), wantMCPWide: true},
		{name: "demoting global keeps mcp-wide", write: setGlobal(false), wantMCPWide: true},
		{name: "demoting mcp-wide leaves a draft", write: setMCPWide(false)},
	}
	previous, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	for _, step := range steps {
		written, err := step.write()
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		got, err := r.FindByID(ctx, p.ID)
		if err != nil {
			t.Fatalf("%s: FindByID: %v", step.name, err)
		}
		if got.Global != step.wantGlobal || got.MCPWide != step.wantMCPWide {
			t.Fatalf("%s: global, mcp_wide = %t, %t, want %t, %t",
				step.name, got.Global, got.MCPWide, step.wantGlobal, step.wantMCPWide)
		}
		if written.Global != got.Global || written.MCPWide != got.MCPWide || !written.UpdatedAt.Equal(got.UpdatedAt) {
			t.Fatalf("%s: returned %+v, want the row as stored (global %t, mcp_wide %t, updated_at %s)",
				step.name, written, got.Global, got.MCPWide, got.UpdatedAt)
		}
		if !got.UpdatedAt.After(previous.UpdatedAt) {
			t.Fatalf("%s: updated_at %s did not move past %s", step.name, got.UpdatedAt, previous.UpdatedAt)
		}
		previous = got
	}

	if _, err := r.SetMCPWide(ctx, ids.New[ids.GatewayKind](), p.ID, true, time.Time{}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SetMCPWide on a foreign gateway: err = %v, want ErrNotFound", err)
	}
	if _, err := r.SetGlobal(ctx, ids.New[ids.GatewayKind](), p.ID, true, time.Time{}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SetGlobal on a foreign gateway: err = %v, want ErrNotFound", err)
	}

	saved := validPolicy(t, gwID, "saved mcp-wide")
	saved.MCPWide = true
	if err := r.Save(ctx, saved); err != nil {
		t.Fatalf("Save mcp-wide: %v", err)
	}
	if got, err := r.FindByID(ctx, saved.ID); err != nil || !got.MCPWide || got.Global {
		t.Fatalf("FindByID after Save = %+v, %v, want mcp_wide round-tripped", got, err)
	}
}

func TestRepository_PlacementCheck_RefusesBothFlags(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-placement-check")

	p := validPolicy(t, gwID, "both flags")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_, err := conn.Pool.Exec(ctx, `UPDATE policies SET global = true, mcp_wide = true WHERE id = $1`, p.ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "policies_global_mcp_wide_check" {
		t.Fatalf("err = %v, want a 23514 from policies_global_mcp_wide_check", err)
	}

	both := validPolicy(t, gwID, "saved with both flags")
	both.Global, both.MCPWide = true, true
	if err := r.Save(ctx, both); !errors.Is(err, domain.ErrInvalidPlacement) {
		t.Fatalf("Save with both flags: err = %v, want ErrInvalidPlacement", err)
	}
}

// The level guard approves a PUT on the placement the caller read. A promotion
// that commits in between must fail the update, or the row would end up with a
// placement and a scope that were never checked together.
func TestRepository_Update_RefusesAStalePlacement(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-placement-update")

	p := validPolicy(t, gwID, "stale placement")
	p.Enabled = false
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	stale := *p
	if _, err := r.SetGlobal(ctx, gwID, p.ID, true, time.Time{}); err != nil {
		t.Fatalf("SetGlobal: %v", err)
	}

	stale.Name = "renamed"
	stale.Enabled = true
	stale.UpdatedAt = time.Now().UTC()
	err := r.Update(ctx, &stale, false)
	if !errors.Is(err, domain.ErrPlacementChanged) || !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrPlacementChanged wrapping ErrConflict", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if !got.Global || got.MCPWide {
		t.Fatalf("global, mcp_wide = %t, %t, want the promotion to stand", got.Global, got.MCPWide)
	}
	if got.Name != p.Name || got.Enabled {
		t.Fatalf("name, enabled = %q, %t, want the stale update unwritten", got.Name, got.Enabled)
	}
}

func TestRepository_Update_LandsWhileThePlacementMatches(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-placement-match")

	p := validPolicy(t, gwID, "matching placement")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := r.SetMCPWide(ctx, gwID, p.ID, true, time.Time{}); err != nil {
		t.Fatalf("SetMCPWide: %v", err)
	}
	current, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	current.Name = "renamed"
	current.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, current, false); err != nil {
		t.Fatalf("Update with the current placement: %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if got.Name != "renamed" || !got.MCPWide || got.Global {
		t.Fatalf("got name %q, global %t, mcp_wide %t, want the rename with the placement kept", got.Name, got.Global, got.MCPWide)
	}
}

// The level guard decides a promotion on the row the scoper read, and takes no
// lock when the promoted policy occupies nothing, as a disabled one does. A PUT
// that turns the policy on in between must fail the promotion, or it would land
// on an enabled row nobody checked.
func TestRepository_PlacementSetters_RefuseAStalePromotion(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-stale-promotion")

	p := validPolicy(t, gwID, "stale promotion")
	p.Enabled = false
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	read, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	enabled := *read
	enabled.Enabled = true
	enabled.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, &enabled, false); err != nil {
		t.Fatalf("Update: %v", err)
	}

	promotions := map[string]func(readAt time.Time) error{
		"SetGlobal": func(readAt time.Time) error {
			_, err := r.SetGlobal(ctx, gwID, p.ID, true, readAt)
			return err
		},
		"SetMCPWide": func(readAt time.Time) error {
			_, err := r.SetMCPWide(ctx, gwID, p.ID, true, readAt)
			return err
		},
	}
	for name, promote := range promotions {
		err := promote(read.UpdatedAt)
		if !errors.Is(err, domain.ErrPlacementChanged) || !errors.Is(err, commonerrors.ErrConflict) {
			t.Fatalf("%s with a stale read: err = %v, want ErrPlacementChanged wrapping ErrConflict", name, err)
		}
	}
	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after the stale promotions: %v", err)
	}
	if got.Global || got.MCPWide || !got.Enabled {
		t.Fatalf("global, mcp_wide, enabled = %t, %t, %t, want the update alone", got.Global, got.MCPWide, got.Enabled)
	}

	if _, err := r.SetMCPWide(ctx, ids.New[ids.GatewayKind](), p.ID, true, got.UpdatedAt); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SetMCPWide on a foreign gateway: err = %v, want ErrNotFound", err)
	}
	written, err := r.SetMCPWide(ctx, gwID, p.ID, true, got.UpdatedAt)
	if err != nil {
		t.Fatalf("SetMCPWide with the current read: %v", err)
	}
	promoted, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after the promotion: %v", err)
	}
	if !promoted.MCPWide {
		t.Fatal("a promotion matching the current row must land")
	}
	if !written.MCPWide || written.Global || !written.UpdatedAt.Equal(promoted.UpdatedAt) {
		t.Fatalf("returned %+v, want the row as stored (updated_at %s)", written, promoted.UpdatedAt)
	}
}

// Every placement write moves updated_at, so of two promotions decided on the
// same read only the first lands.
func TestRepository_PlacementSetters_RacingPromotionsConflict(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-racing-promotions")

	p := validPolicy(t, gwID, "racing promotions")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	read, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	if _, err := r.SetGlobal(ctx, gwID, p.ID, true, read.UpdatedAt); err != nil {
		t.Fatalf("first promotion: %v", err)
	}
	if _, err := r.SetMCPWide(ctx, gwID, p.ID, true, read.UpdatedAt); !errors.Is(err, domain.ErrPlacementChanged) {
		t.Fatalf("second promotion on the same read: err = %v, want ErrPlacementChanged", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if !got.Global || got.MCPWide {
		t.Fatalf("global, mcp_wide = %t, %t, want the first promotion to stand", got.Global, got.MCPWide)
	}
	if got.UpdatedAt.Equal(read.UpdatedAt) {
		t.Fatal("a placement write must move updated_at")
	}

	if _, err := r.SetGlobal(ctx, gwID, p.ID, false, time.Time{}); err != nil {
		t.Fatalf("an unconditional demotion after the read: %v", err)
	}
}

func TestRepository_ConsumerPolicyJunction_AttachDetachRoundTrip(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-junction")
	c1 := seedConsumer(t, conn, gwID, "junction-a")
	c2 := seedConsumer(t, conn, gwID, "junction-b")
	consumers := consumerrepo.NewRepository(conn, outboxrepo.NewRepository(conn))

	p := validPolicy(t, gwID, "linked")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Junctions are written exclusively through the consumer repository.
	if err := consumers.AttachPolicy(ctx, c1, p.ID); err != nil {
		t.Fatalf("AttachPolicy c1: %v", err)
	}
	if err := consumers.AttachPolicy(ctx, c2, p.ID); err != nil {
		t.Fatalf("AttachPolicy c2: %v", err)
	}
	// Idempotent re-attach must not error.
	if err := consumers.AttachPolicy(ctx, c1, p.ID); err != nil {
		t.Fatalf("AttachPolicy c1 (idempotent): %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.ConsumerIDs) != 2 {
		t.Fatalf("ConsumerIDs projection lost data: %+v", got.ConsumerIDs)
	}

	if err := consumers.DetachPolicy(ctx, c1, p.ID); err != nil {
		t.Fatalf("DetachPolicy c1: %v", err)
	}
	got, err = r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after detach: %v", err)
	}
	if len(got.ConsumerIDs) != 1 || got.ConsumerIDs[0] != c2 {
		t.Fatalf("detach did not leave exactly c2: %+v", got.ConsumerIDs)
	}
}

func TestRepository_DeletePolicy_CascadesJunction(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-cascade")
	c1 := seedConsumer(t, conn, gwID, "cascade-a")
	consumers := consumerrepo.NewRepository(conn, outboxrepo.NewRepository(conn))

	p := validPolicy(t, gwID, "cascade")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := consumers.AttachPolicy(ctx, c1, p.ID); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}
	if err := r.Delete(ctx, gwID, p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	var count int
	if err := conn.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM consumer_policy WHERE policy_id = $1", p.ID).Scan(&count); err != nil {
		t.Fatalf("count junction: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected junction rows to be cascaded on policy delete, got %d", count)
	}
}

func TestRepository_MCPScope_RoundTrip(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-scope")
	snowflake := seedMCPRegistry(t, conn, gwID, "scope-snowflake")
	jira := seedMCPRegistry(t, conn, gwID, "scope-jira")

	full := &domain.MCPScope{
		RegistryIDs:  []ids.RegistryID{jira},
		Tools:        []domain.MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}},
		Groups:       []string{"Finanzas"},
		ExceptGroups: []string{"Contractors"},
	}
	unscoped := scopedPolicy(t, gwID, "unscoped", nil)
	pruned := scopedPolicy(t, gwID, "pruned", &domain.MCPScope{})
	scoped := scopedPolicy(t, gwID, "scoped", full)
	for _, p := range []*domain.Policy{unscoped, pruned, scoped} {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save %s: %v", p.Name, err)
		}
	}

	got, err := r.FindByID(ctx, unscoped.ID)
	if err != nil {
		t.Fatalf("FindByID unscoped: %v", err)
	}
	if got.MCPScope != nil {
		t.Fatalf("nil scope came back as %+v, want nil", got.MCPScope)
	}
	if isNull, _ := rawMCPScope(t, conn, unscoped.ID); !isNull {
		t.Fatal("nil scope must be stored as SQL NULL")
	}

	got, err = r.FindByID(ctx, pruned.ID)
	if err != nil {
		t.Fatalf("FindByID pruned: %v", err)
	}
	if got.MCPScope == nil || !got.MCPScope.IsEmpty() {
		t.Fatalf("empty scope came back as %+v, want &MCPScope{}", got.MCPScope)
	}
	if isNull, text := rawMCPScope(t, conn, pruned.ID); isNull || text != "{}" {
		t.Fatalf("empty scope stored as (null=%v, %q), want '{}'", isNull, text)
	}

	got, err = r.FindByID(ctx, scoped.ID)
	if err != nil {
		t.Fatalf("FindByID scoped: %v", err)
	}
	if !reflect.DeepEqual(got.MCPScope, full) {
		t.Fatalf("scope round-trip lost data:\n got %+v\nwant %+v", got.MCPScope, full)
	}

	byIDs, err := r.FindByIDs(ctx, gwID, []ids.PolicyID{scoped.ID, pruned.ID})
	if err != nil {
		t.Fatalf("FindByIDs: %v", err)
	}
	if len(byIDs) != 2 {
		t.Fatalf("FindByIDs len = %d, want 2", len(byIDs))
	}
	for _, p := range byIDs {
		if p.ID == scoped.ID && !reflect.DeepEqual(p.MCPScope, full) {
			t.Fatalf("FindByIDs lost scope: %+v", p.MCPScope)
		}
		if p.ID == pruned.ID && (p.MCPScope == nil || !p.MCPScope.IsEmpty()) {
			t.Fatalf("FindByIDs turned {} into %+v", p.MCPScope)
		}
	}
	all, err := r.ListByGateway(ctx, gwID)
	if err != nil {
		t.Fatalf("ListByGateway: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListByGateway len = %d, want 3", len(all))
	}
}

func TestRepository_MCPScope_UpdateTransitions(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-scope-upd")
	snowflake := seedMCPRegistry(t, conn, gwID, "upd-snowflake")

	p := scopedPolicy(t, gwID, "transitions", nil)
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	p.MCPScope = &domain.MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}
	p.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, p, true); err != nil {
		t.Fatalf("Update nil -> scope: %v", err)
	}
	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.MCPScope == nil || len(got.MCPScope.RegistryIDs) != 1 || got.MCPScope.RegistryIDs[0] != snowflake {
		t.Fatalf("scope not persisted on update: %+v", got.MCPScope)
	}

	p.MCPScope = &domain.MCPScope{}
	if err := r.Update(ctx, p, true); err != nil {
		t.Fatalf("Update scope -> {}: %v", err)
	}
	if isNull, text := rawMCPScope(t, conn, p.ID); isNull || text != "{}" {
		t.Fatalf("empty scope stored as (null=%v, %q), want '{}'", isNull, text)
	}

	p.MCPScope = nil
	if err := r.Update(ctx, p, true); err != nil {
		t.Fatalf("Update {} -> nil: %v", err)
	}
	if isNull, _ := rawMCPScope(t, conn, p.ID); !isNull {
		t.Fatal("clearing the scope must write SQL NULL")
	}
	got, err = r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after clear: %v", err)
	}
	if got.MCPScope != nil {
		t.Fatalf("cleared scope came back as %+v, want nil", got.MCPScope)
	}
}

// An update that did not carry an mcp_scope must leave the column alone. The
// caller read the policy before a registry delete pruned it; writing the value
// it read back would resurrect a registry that no longer exists, and the prune
// cannot defend itself because the caller never took its row lock.
func TestRepository_Update_WithoutScopeWriteKeepsTheStoredScope(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-scope-nowrite")
	snowflake := seedMCPRegistry(t, conn, gwID, "nowrite-snowflake")

	p := scopedPolicy(t, gwID, "no-write", &domain.MCPScope{RegistryIDs: []ids.RegistryID{snowflake}})
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Somebody else prunes the scope to {} while this caller holds a stale read.
	stale := *p
	if _, err := conn.Pool.Exec(ctx, `UPDATE policies SET mcp_scope = '{}' WHERE id = $1`, p.ID); err != nil {
		t.Fatalf("prune: %v", err)
	}

	stale.Name = "renamed"
	stale.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, &stale, false); err != nil {
		t.Fatalf("Update without scope write: %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Name != "renamed" {
		t.Fatalf("Name = %q, want the update to have landed", got.Name)
	}
	if got.MCPScope == nil || !got.MCPScope.IsEmpty() {
		t.Fatalf("MCPScope = %+v, want the pruned {} to have survived", got.MCPScope)
	}
	if isNull, text := rawMCPScope(t, conn, p.ID); isNull || text != "{}" {
		t.Fatalf("stored scope = (null=%v, %q), want '{}'", isNull, text)
	}
}

func TestRepository_List_FilterByRegistryID(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-scope-list")
	snowflake := seedMCPRegistry(t, conn, gwID, "list-snowflake")
	jira := seedMCPRegistry(t, conn, gwID, "list-jira")

	byRegistry := scopedPolicy(t, gwID, "by-registry", &domain.MCPScope{RegistryIDs: []ids.RegistryID{snowflake}})
	byTool := scopedPolicy(t, gwID, "by-tool", &domain.MCPScope{Tools: []domain.MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}})
	other := scopedPolicy(t, gwID, "other-registry", &domain.MCPScope{RegistryIDs: []ids.RegistryID{jira}})
	pruned := scopedPolicy(t, gwID, "pruned", &domain.MCPScope{})
	unscoped := scopedPolicy(t, gwID, "unscoped", nil)
	for _, p := range []*domain.Policy{byRegistry, byTool, other, pruned, unscoped} {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save %s: %v", p.Name, err)
		}
	}

	page := listing.Page{Number: 1, Size: 10}
	items, total, err := r.List(ctx, domain.ListFilter{GatewayID: gwID, RegistryID: &snowflake, Page: page})
	if err != nil {
		t.Fatalf("List registry_id=snowflake: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("List(snowflake) total=%d len=%d, want 2/2: %v", total, len(items), policyIDs(items))
	}
	for _, p := range items {
		if p.ID != byRegistry.ID && p.ID != byTool.ID {
			t.Fatalf("List(snowflake) returned unexpected policy %s (%s)", p.ID, p.Name)
		}
	}

	items, total, err = r.List(ctx, domain.ListFilter{GatewayID: gwID, RegistryID: &jira, Page: page})
	if err != nil {
		t.Fatalf("List registry_id=jira: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != other.ID {
		t.Fatalf("List(jira) total=%d items=%v, want only %s", total, policyIDs(items), other.ID)
	}

	unknown := ids.New[ids.RegistryKind]()
	items, total, err = r.List(ctx, domain.ListFilter{GatewayID: gwID, RegistryID: &unknown, Page: page})
	if err != nil {
		t.Fatalf("List registry_id=unknown: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("List(unknown) total=%d len=%d, want 0/0", total, len(items))
	}

	items, total, err = r.List(ctx, domain.ListFilter{GatewayID: gwID, Page: page})
	if err != nil {
		t.Fatalf("List without registry_id: %v", err)
	}
	if total != 5 || len(items) != 5 {
		t.Fatalf("List(all) total=%d len=%d, want 5/5", total, len(items))
	}
}

func TestRepository_DeleteRegistry_PrunesMCPScopeInSameTx(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-scope-prune")
	otherGW := seedGateway(t, gw, "pgw-scope-prune-other")
	keeper := seedMCPRegistry(t, conn, gwID, "prune-keeper")
	victim := seedMCPRegistry(t, conn, gwID, "prune-victim")

	several := scopedPolicy(t, gwID, "several-registries", &domain.MCPScope{
		RegistryIDs: []ids.RegistryID{keeper, victim},
		Groups:      []string{"Finanzas"},
	})
	only := scopedPolicy(t, gwID, "only-victim-tool", &domain.MCPScope{
		Tools: []domain.MCPToolRef{{RegistryID: victim, Tool: "run_query"}},
	})
	untouched := scopedPolicy(t, gwID, "keeper-only", &domain.MCPScope{RegistryIDs: []ids.RegistryID{keeper}})
	unscoped := scopedPolicy(t, gwID, "unscoped", nil)
	foreign := scopedPolicy(t, otherGW, "foreign-reference", &domain.MCPScope{RegistryIDs: []ids.RegistryID{victim}})
	for _, p := range []*domain.Policy{several, only, untouched, unscoped, foreign} {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save %s: %v", p.Name, err)
		}
	}
	before, err := r.FindByID(ctx, untouched.ID)
	if err != nil {
		t.Fatalf("FindByID untouched: %v", err)
	}

	cipher, err := crypto.NewCipher("functional-test-secret-0123456789abcdef")
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	registries := registryrepo.NewRepository(conn, cipher, outboxrepo.NewRepository(conn),
		registryrepo.WithDeleteHook(r.PruneRegistryReferencesTx))
	report, err := registries.Delete(ctx, gwID, victim)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if report.Empty() || len(report.Policies) != 2 {
		t.Fatalf("report = %+v, want exactly the two pruned policies", report)
	}
	emptied := map[ids.PolicyID]bool{}
	for _, prune := range report.Policies {
		emptied[prune.PolicyID] = prune.Emptied
	}
	if got, ok := emptied[several.ID]; !ok || got {
		t.Fatalf("report for %s = (present=%v, emptied=%v), want present and not emptied", several.Name, ok, got)
	}
	if got, ok := emptied[only.ID]; !ok || !got {
		t.Fatalf("report for %s = (present=%v, emptied=%v), want present and emptied", only.Name, ok, got)
	}

	got, err := r.FindByID(ctx, several.ID)
	if err != nil {
		t.Fatalf("FindByID several: %v", err)
	}
	if got.MCPScope == nil || len(got.MCPScope.RegistryIDs) != 1 || got.MCPScope.RegistryIDs[0] != keeper {
		t.Fatalf("several-registries scope = %+v, want only %s", got.MCPScope, keeper)
	}
	if len(got.MCPScope.Groups) != 1 || got.MCPScope.Groups[0] != "Finanzas" {
		t.Fatalf("prune must keep the principal dimension: %+v", got.MCPScope)
	}
	if !got.UpdatedAt.After(several.UpdatedAt) {
		t.Fatalf("updated_at not bumped: %s <= %s", got.UpdatedAt, several.UpdatedAt)
	}

	got, err = r.FindByID(ctx, only.ID)
	if err != nil {
		t.Fatalf("FindByID only: %v", err)
	}
	if got.MCPScope == nil || !got.MCPScope.IsEmpty() {
		t.Fatalf("only-victim-tool scope = %+v, want {}", got.MCPScope)
	}
	if isNull, text := rawMCPScope(t, conn, only.ID); isNull || text != "{}" {
		t.Fatalf("pruned scope stored as (null=%v, %q), want '{}' and never NULL", isNull, text)
	}
	if ok, _ := got.MCPScope.Matches(domain.MCPTarget{RegistryID: keeper, Tool: "run_query"}, domain.MCPCaller{}); ok {
		t.Fatal("a pruned {} scope must not match any target")
	}

	got, err = r.FindByID(ctx, untouched.ID)
	if err != nil {
		t.Fatalf("FindByID untouched: %v", err)
	}
	if !reflect.DeepEqual(got.MCPScope, before.MCPScope) || !got.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("keeper-only policy was rewritten: %+v (updated_at %s -> %s)", got.MCPScope, before.UpdatedAt, got.UpdatedAt)
	}
	if isNull, _ := rawMCPScope(t, conn, unscoped.ID); !isNull {
		t.Fatal("an unscoped policy must stay NULL after a prune")
	}
	got, err = r.FindByID(ctx, foreign.ID)
	if err != nil {
		t.Fatalf("FindByID foreign: %v", err)
	}
	if got.MCPScope == nil || len(got.MCPScope.RegistryIDs) != 1 || got.MCPScope.RegistryIDs[0] != victim {
		t.Fatalf("prune crossed the gateway boundary: %+v", got.MCPScope)
	}
	if _, err := newRegistryRepo(conn).FindByID(ctx, victim); !errors.Is(err, registrydomain.ErrNotFound) {
		t.Fatalf("registry FindByID after delete err = %v, want ErrNotFound", err)
	}
}
