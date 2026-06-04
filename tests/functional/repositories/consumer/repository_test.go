//go:build functional

package consumer_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	_ "github.com/NeuralTrust/AgentGateway/pkg/infra/database/migrations"
	repo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/consumer"
	gatewayrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/gateway"
	registryrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/registry"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixture struct {
	repo *repo.Repository
	gw   *gatewayrepo.Repository
	be   *registryrepo.Repository
}

func setupRepo(t *testing.T) fixture {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping consumer repository integration test")
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
		_, _ = pool.Exec(context.Background(),
			"TRUNCATE TABLE consumer_registry, consumers, registries, gateways CASCADE")
		pool.Close()
	})

	return fixture{
		repo: repo.NewRepository(conn),
		gw:   gatewayrepo.NewRepository(conn),
		be:   registryrepo.NewRepository(conn),
	}
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

func seedRegistry(t *testing.T, be *registryrepo.Repository, gwID ids.GatewayID, name string) ids.RegistryID {
	t.Helper()
	b, err := registrydomain.NewRegistry(gwID, name, "openai", nil, "", 1, registrydomain.NewAPIKeyAuth("sk-test"), nil)
	if err != nil {
		t.Fatalf("backend domain.NewRegistry: %v", err)
	}
	if err := be.Save(context.Background(), b); err != nil {
		t.Fatalf("backend Save: %v", err)
	}
	return b.ID
}

func validConsumer(t *testing.T, gwID ids.GatewayID, name string, beIDs ...ids.RegistryID) *domain.Consumer {
	t.Helper()
	c, err := domain.New(domain.CreateParams{
		GatewayID:   gwID,
		Name:        name,
		Type:        domain.TypeLLM,
		Path:        "/v1/" + uuid.NewString(),
		RegistryIDs: beIDs,
	})
	if err != nil {
		t.Fatalf("consumer domain.New: %v", err)
	}
	return c
}

func saveWithRegistries(t *testing.T, f fixture, c *domain.Consumer) {
	t.Helper()
	ctx := context.Background()
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for _, rid := range c.RegistryIDs {
		if err := f.repo.AttachRegistry(ctx, c.ID, rid); err != nil {
			t.Fatalf("AttachRegistry: %v", err)
		}
	}
}

func TestRepository_SaveAndFindByID(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool")
	beID := seedRegistry(t, f.be, gwID, "be1")

	c := validConsumer(t, gwID, "openai-chat", beID)
	c.Headers = map[string]string{"X-Tenant": "acme"}

	saveWithRegistries(t, f, c)

	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != c.ID || got.GatewayID != gwID {
		t.Fatalf("FindByID returned %+v", got)
	}
	if got.Type != domain.TypeLLM {
		t.Fatalf("Type = %q", got.Type)
	}
	if len(got.RegistryIDs) != 1 || got.RegistryIDs[0] != beID {
		t.Fatalf("RegistryIDs = %v, want [%s]", got.RegistryIDs, beID)
	}
	if got.Headers["X-Tenant"] != "acme" {
		t.Fatalf("Headers lost data: %+v", got.Headers)
	}
	if got.Path != c.Path {
		t.Fatalf("Path = %q, want %q", got.Path, c.Path)
	}
	if got.Algorithm == "" {
		t.Fatalf("Algorithm should default, got empty")
	}
}

func TestRepository_SaveAndFindByID_RoundTripsFallback(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool-fb")
	poolBE := seedRegistry(t, f.be, gwID, "be-pool")
	fbBE := seedRegistry(t, f.be, gwID, "be-fallback")

	c := validConsumer(t, gwID, "fb-consumer", poolBE)
	c.Fallback = &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx, domain.TriggerHTTP429},
		Budget:   domain.FallbackBudget{MaxAttempts: 6, MaxTotalLatency: 5 * time.Second, MaxCostUSD: 1.5},
		Chain:    registrydomain.Registries{fbBE},
	}

	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Fallback == nil {
		t.Fatal("Fallback was not persisted")
	}
	if !got.Fallback.Enabled || got.Fallback.Budget.MaxAttempts != 6 {
		t.Fatalf("Fallback round-trip mismatch: %+v", got.Fallback)
	}
	if got.Fallback.Budget.MaxTotalLatency != 5*time.Second {
		t.Fatalf("Fallback latency = %v, want 5s", got.Fallback.Budget.MaxTotalLatency)
	}
	if len(got.Fallback.Chain) != 1 || got.Fallback.Chain[0] != fbBE {
		t.Fatalf("Fallback chain = %v, want [%s]", got.Fallback.Chain, fbBE)
	}
	if len(got.Fallback.Triggers) != 2 {
		t.Fatalf("Fallback triggers = %v, want 2", got.Fallback.Triggers)
	}
}

func TestRepository_SaveAndFindByID_RoundTripsModelPolicies(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool-mp")
	poolBE := seedRegistry(t, f.be, gwID, "be-mp-pool")
	fbBE := seedRegistry(t, f.be, gwID, "be-mp-fallback")

	c := validConsumer(t, gwID, "mp-consumer", poolBE)
	c.Fallback = &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
		Budget:   domain.FallbackBudget{MaxAttempts: 3},
		Chain:    registrydomain.Registries{fbBE},
	}
	c.ModelPolicies = domain.ModelPolicies{
		poolBE: {Allowed: []string{"gpt-4o", "gpt-4o-mini"}, Default: "gpt-4o"},
		fbBE:   {Default: "claude-3-5-sonnet"},
	}

	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.ModelPolicies) != 2 {
		t.Fatalf("ModelPolicies = %+v, want 2 entries", got.ModelPolicies)
	}
	pool, ok := got.ModelPolicies.For(poolBE)
	if !ok || pool.Default != "gpt-4o" || len(pool.Allowed) != 2 {
		t.Fatalf("pool policy round-trip mismatch: %+v", pool)
	}
	fb, ok := got.ModelPolicies.For(fbBE)
	if !ok || fb.Default != "claude-3-5-sonnet" || len(fb.Allowed) != 0 {
		t.Fatalf("fallback policy round-trip mismatch: %+v", fb)
	}
}

func TestRepository_FindByID_NotFound(t *testing.T) {
	f := setupRepo(t)
	_, err := f.repo.FindByID(context.Background(), ids.New[ids.ConsumerKind]())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Save_DuplicateNameForSameGateway(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool3")
	beID := seedRegistry(t, f.be, gwID, "be3")

	c1 := validConsumer(t, gwID, "dupe", beID)
	if err := f.repo.Save(ctx, c1); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	c2 := validConsumer(t, gwID, "dupe", beID)
	err := f.repo.Save(ctx, c2)
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestRepository_Save_DuplicatePathForSameGateway(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool-path")
	beID := seedRegistry(t, f.be, gwID, "be-path")

	c1 := validConsumer(t, gwID, "first", beID)
	c1.Path = "/v1/shared/path"
	if err := f.repo.Save(ctx, c1); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	c2 := validConsumer(t, gwID, "second", beID)
	c2.Path = "/v1/shared/path"
	err := f.repo.Save(ctx, c2)
	if !errors.Is(err, domain.ErrPathAlreadyExists) {
		t.Fatalf("err = %v, want ErrPathAlreadyExists", err)
	}
}

func TestRepository_Save_SamePathDifferentGatewaysAllowed(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, f.gw, "g-p1")
	gw2 := seedGateway(t, f.gw, "g-p2")
	be1 := seedRegistry(t, f.be, gw1, "be-p1")
	be2 := seedRegistry(t, f.be, gw2, "be-p2")

	c1 := validConsumer(t, gw1, "c1", be1)
	c1.Path = "/v1/chat/completions"
	if err := f.repo.Save(ctx, c1); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	c2 := validConsumer(t, gw2, "c2", be2)
	c2.Path = "/v1/chat/completions"
	if err := f.repo.Save(ctx, c2); err != nil {
		t.Fatalf("second Save: %v", err)
	}
}

func TestRepository_Save_SameNameDifferentGatewaysAllowed(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, f.gw, "g-a")
	gw2 := seedGateway(t, f.gw, "g-b")
	be1 := seedRegistry(t, f.be, gw1, "be-a")
	be2 := seedRegistry(t, f.be, gw2, "be-b")

	if err := f.repo.Save(ctx, validConsumer(t, gw1, "shared", be1)); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := f.repo.Save(ctx, validConsumer(t, gw2, "shared", be2)); err != nil {
		t.Fatalf("second Save: %v", err)
	}
}

func TestRepository_Save_InvalidGatewayID(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	orphanGW := ids.New[ids.GatewayKind]()
	c := validConsumer(t, orphanGW, "orphan", ids.New[ids.RegistryKind]())
	err := f.repo.Save(ctx, c)
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestRepository_AttachRegistry_InvalidRegistryID(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool-be")
	c := validConsumer(t, gwID, "with-ghost")
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	ghostBE := ids.New[ids.RegistryKind]()
	err := f.repo.AttachRegistry(ctx, c.ID, ghostBE)
	if !errors.Is(err, registrydomain.ErrInvalidRegistryID) {
		t.Fatalf("err = %v, want ErrInvalidRegistryID", err)
	}
}

func TestRepository_RebindsBackendsViaAttachDetach(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "rebind")
	be1 := seedRegistry(t, f.be, gwID, "be-x")
	be2 := seedRegistry(t, f.be, gwID, "be-y")
	be3 := seedRegistry(t, f.be, gwID, "be-z")

	c := validConsumer(t, gwID, "rb", be1, be2)
	saveWithRegistries(t, f, c)

	if err := f.repo.DetachRegistry(ctx, c.ID, be1); err != nil {
		t.Fatalf("DetachRegistry: %v", err)
	}
	if err := f.repo.AttachRegistry(ctx, c.ID, be3); err != nil {
		t.Fatalf("AttachRegistry: %v", err)
	}

	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.RegistryIDs) != 2 {
		t.Fatalf("RegistryIDs len = %d, want 2", len(got.RegistryIDs))
	}
	have := map[ids.RegistryID]bool{got.RegistryIDs[0]: true, got.RegistryIDs[1]: true}
	if !have[be2] || !have[be3] {
		t.Fatalf("RegistryIDs = %v, want [%s,%s]", got.RegistryIDs, be2, be3)
	}
}

func TestRepository_Update_NotFound(t *testing.T) {
	f := setupRepo(t)
	gwID := seedGateway(t, f.gw, "pool-u2")
	beID := seedRegistry(t, f.be, gwID, "be-u2")
	c := validConsumer(t, gwID, "ghost", beID)
	err := f.repo.Update(context.Background(), c)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool-d")
	beID := seedRegistry(t, f.be, gwID, "be-d")
	c := validConsumer(t, gwID, "victim", beID)
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := f.repo.Delete(ctx, c.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := f.repo.FindByID(ctx, c.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete_NotFound(t *testing.T) {
	f := setupRepo(t)
	err := f.repo.Delete(context.Background(), ids.New[ids.ConsumerKind]())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_List_FilterByGatewayAndName(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, f.gw, "gw-l1")
	gw2 := seedGateway(t, f.gw, "gw-l2")
	be1 := seedRegistry(t, f.be, gw1, "be-l1")
	be2 := seedRegistry(t, f.be, gw2, "be-l2")

	mustSave := func(c *domain.Consumer) {
		if err := f.repo.Save(ctx, c); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	mustSave(validConsumer(t, gw1, "openai-prod", be1))
	mustSave(validConsumer(t, gw1, "openai-stag", be1))
	mustSave(validConsumer(t, gw2, "anthropic-prod", be2))

	items, total, err := f.repo.List(ctx, domain.ListFilter{GatewayID: gw1, Page: 1, Size: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("List(gw1) total=%d len=%d, want 2/2", total, len(items))
	}

	items, total, err = f.repo.List(ctx, domain.ListFilter{NameContains: "anthropic", Page: 1, Size: 10})
	if err != nil {
		t.Fatalf("List name: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Name != "anthropic-prod" {
		t.Fatalf("List(name) returned %+v", items)
	}
}

func TestRepository_DeleteBackend_FailsWhenReferencedByConsumer(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool-bd")
	beID := seedRegistry(t, f.be, gwID, "be-bd")

	saveWithRegistries(t, f, validConsumer(t, gwID, "uses-be", beID))
	err := f.be.Delete(ctx, beID)
	if !errors.Is(err, registrydomain.ErrHasDependents) {
		t.Fatalf("err = %v, want registrydomain.ErrHasDependents", err)
	}
}

func TestRepository_DeleteBackend_FailsWhenReferencedByFallbackChain(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool-fbd")
	poolBE := seedRegistry(t, f.be, gwID, "be-pool-fbd")
	fbBE := seedRegistry(t, f.be, gwID, "be-fallback-only")

	c := validConsumer(t, gwID, "fb-only-consumer", poolBE)
	c.Fallback = &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
		Budget:   domain.FallbackBudget{MaxAttempts: 3},
		Chain:    registrydomain.Registries{fbBE},
	}
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	err := f.be.Delete(ctx, fbBE)
	if !errors.Is(err, registrydomain.ErrHasDependents) {
		t.Fatalf("err = %v, want registrydomain.ErrHasDependents", err)
	}
}
