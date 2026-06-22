//go:build functional

package policy_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	consumerrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/consumer"
	gatewayrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/policy"
	registryrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
	"github.com/jackc/pgx/v5/pgxpool"
)

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

	return repo.NewRepository(conn), gatewayrepo.NewRepository(conn), conn
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
	if err := registryrepo.NewRepository(conn).Save(ctx, reg); err != nil {
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
	if err := consumerrepo.NewRepository(conn).Save(ctx, cons); err != nil {
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
		map[string]any{"limit": 100}, []domain.Stage{domain.StagePreRequest}, "round-trip description", domain.ModeEnforce)
	if err != nil {
		t.Fatalf("policy domain.NewPolicy: %v", err)
	}
	return p
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

	p, err := domain.NewPolicy(gwID, "empty", "cors", true, 0, false, nil, nil, "", domain.ModeEnforce)
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
	p.Slug = "cors"
	p.Enabled = false
	p.Stages = []domain.Stage{domain.StagePostResponse}
	p.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, p); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if got.Name != "alpha-renamed" {
		t.Fatalf("Name = %q, want alpha-renamed", got.Name)
	}
	if got.Slug != "cors" || got.Enabled {
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
	err := r.Update(context.Background(), p)
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
	if err := r.Delete(ctx, p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.FindByID(ctx, p.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete_NotFound(t *testing.T) {
	r, _, _ := setupRepo(t)
	err := r.Delete(context.Background(), ids.New[ids.PolicyKind]())
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

	items, total, err := r.List(ctx, domain.ListFilter{GatewayID: gw1, Page: 1, Size: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("List(gw1) total=%d len=%d, want 2/2", total, len(items))
	}

	items, total, err = r.List(ctx, domain.ListFilter{NameContains: "anthropic", Page: 1, Size: 10})
	if err != nil {
		t.Fatalf("List name: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Name != "anthropic-prod" {
		t.Fatalf("List(name) returned %+v", items)
	}

	items, total, err = r.List(ctx, domain.ListFilter{Page: 1, Size: 10})
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("List all total=%d len=%d, want 3/3", total, len(items))
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
	if err := r.SetGlobal(ctx, global.ID, true); err != nil {
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

func TestRepository_ConsumerPolicyJunction_AttachDetachRoundTrip(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-junction")
	c1 := seedConsumer(t, conn, gwID, "junction-a")
	c2 := seedConsumer(t, conn, gwID, "junction-b")
	consumers := consumerrepo.NewRepository(conn)

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
	consumers := consumerrepo.NewRepository(conn)

	p := validPolicy(t, gwID, "cascade")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := consumers.AttachPolicy(ctx, c1, p.ID); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}
	if err := r.Delete(ctx, p.ID); err != nil {
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
