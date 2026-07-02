//go:build functional

package consumer_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/consumer"
	gatewayrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	registryrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
	rolerepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/role"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newRegistryRepo(conn *database.Connection) *registryrepo.Repository {
	cipher, err := crypto.NewCipher("functional-test-secret-0123456789abcdef")
	if err != nil {
		panic(err)
	}
	return registryrepo.NewRepository(conn, cipher, outboxrepo.NewRepository(conn))
}

type fixture struct {
	repo  *repo.Repository
	gw    *gatewayrepo.Repository
	be    *registryrepo.Repository
	roles *rolerepo.Repository
	conn  *database.Connection
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
			"TRUNCATE TABLE consumer_role, consumer_registry, consumers, roles, registries, gateways CASCADE")
		pool.Close()
	})

	appender := outboxrepo.NewRepository(conn)
	return fixture{
		repo:  repo.NewRepository(conn, appender),
		gw:    gatewayrepo.NewRepository(conn, appender),
		be:    newRegistryRepo(conn),
		roles: rolerepo.NewRepository(conn, appender),
		conn:  conn,
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
	b, err := registrydomain.NewLLMRegistry(gwID, name, "", &registrydomain.LLMTarget{
		Provider: "openai",
		Auth:     registrydomain.NewAPIKeyAuth("sk-test"),
	})
	if err != nil {
		t.Fatalf("backend domain.NewLLMRegistry: %v", err)
	}
	if err := be.Save(context.Background(), b); err != nil {
		t.Fatalf("backend Save: %v", err)
	}
	return b.ID
}

func seedRole(t *testing.T, roles *rolerepo.Repository, gwID ids.GatewayID, name string) ids.RoleID {
	t.Helper()
	role, err := roledomain.New(roledomain.CreateParams{
		GatewayID: gwID,
		Name:      name,
	})
	if err != nil {
		t.Fatalf("role domain.New: %v", err)
	}
	if err := roles.Save(context.Background(), role); err != nil {
		t.Fatalf("role Save: %v", err)
	}
	return role.ID
}

func validConsumer(t *testing.T, gwID ids.GatewayID, name string, beIDs ...ids.RegistryID) *domain.Consumer {
	t.Helper()
	c, err := domain.New(domain.CreateParams{
		GatewayID:   gwID,
		Name:        name,
		Type:        domain.TypeLLM,
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
		weight := c.WeightFor(rid)
		if err := f.repo.AttachRegistry(ctx, c.ID, rid, &weight); err != nil {
			t.Fatalf("AttachRegistry: %v", err)
		}
	}
}

func weightPtr(i int) *int { return &i }

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
	if got.Slug != c.Slug {
		t.Fatalf("Slug = %q, want %q", got.Slug, c.Slug)
	}
	if got.RoutingMode != domain.RoutingModeInline {
		t.Fatalf("RoutingMode = %q, want %q", got.RoutingMode, domain.RoutingModeInline)
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
		Budget:   domain.FallbackBudget{MaxAttempts: 6, MaxTotalLatency: 5 * time.Second},
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

func TestRepository_Save_DuplicateSlug(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool-slug")
	beID := seedRegistry(t, f.be, gwID, "be-slug")

	c1 := validConsumer(t, gwID, "first", beID)
	if err := f.repo.Save(ctx, c1); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	c2 := validConsumer(t, gwID, "second", beID)
	c2.Slug = c1.Slug
	err := f.repo.Save(ctx, c2)
	if !errors.Is(err, domain.ErrSlugAlreadyExists) {
		t.Fatalf("err = %v, want ErrSlugAlreadyExists", err)
	}
}

func TestRepository_Save_DuplicateSlugAcrossGatewaysRejected(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, f.gw, "g-p1")
	gw2 := seedGateway(t, f.gw, "g-p2")
	be1 := seedRegistry(t, f.be, gw1, "be-p1")
	be2 := seedRegistry(t, f.be, gw2, "be-p2")

	c1 := validConsumer(t, gw1, "c1", be1)
	if err := f.repo.Save(ctx, c1); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	c2 := validConsumer(t, gw2, "c2", be2)
	c2.Slug = c1.Slug
	if err := f.repo.Save(ctx, c2); !errors.Is(err, domain.ErrSlugAlreadyExists) {
		t.Fatalf("err = %v, want ErrSlugAlreadyExists (slug uniqueness is global)", err)
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
	err := f.repo.AttachRegistry(ctx, c.ID, ghostBE, weightPtr(1))
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
	if err := f.repo.AttachRegistry(ctx, c.ID, be3, weightPtr(1)); err != nil {
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

func TestRepository_RegistryWeights_PerAssociation(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "weights")
	shared := seedRegistry(t, f.be, gwID, "shared-be")

	c1 := validConsumer(t, gwID, "c1", shared)
	c1.RegistryWeights = map[ids.RegistryID]int{shared: 5}
	saveWithRegistries(t, f, c1)

	c2 := validConsumer(t, gwID, "c2", shared)
	c2.RegistryWeights = map[ids.RegistryID]int{shared: 2}
	saveWithRegistries(t, f, c2)

	got1, err := f.repo.FindByID(ctx, c1.ID)
	if err != nil {
		t.Fatalf("FindByID c1: %v", err)
	}
	if got1.RegistryWeights[shared] != 5 {
		t.Fatalf("c1 weight = %d, want 5", got1.RegistryWeights[shared])
	}

	got2, err := f.repo.FindByID(ctx, c2.ID)
	if err != nil {
		t.Fatalf("FindByID c2: %v", err)
	}
	if got2.RegistryWeights[shared] != 2 {
		t.Fatalf("c2 weight = %d, want 2", got2.RegistryWeights[shared])
	}
}

func TestRepository_AttachRegistry_PersistsWeight(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "attach-weight")
	beID := seedRegistry(t, f.be, gwID, "attach-weight-be")
	c := validConsumer(t, gwID, "attach-weight-consumer")
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := f.repo.AttachRegistry(ctx, c.ID, beID, weightPtr(7)); err != nil {
		t.Fatalf("AttachRegistry: %v", err)
	}
	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.RegistryWeights[beID] != 7 {
		t.Fatalf("weight = %d, want 7", got.RegistryWeights[beID])
	}

	if err := f.repo.AttachRegistry(ctx, c.ID, beID, weightPtr(3)); err != nil {
		t.Fatalf("AttachRegistry re-attach: %v", err)
	}
	got, err = f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID after re-attach: %v", err)
	}
	if got.RegistryWeights[beID] != 3 {
		t.Fatalf("weight after re-attach = %d, want 3 (ON CONFLICT update)", got.RegistryWeights[beID])
	}

	if err := f.repo.AttachRegistry(ctx, c.ID, beID, nil); err != nil {
		t.Fatalf("AttachRegistry re-attach without weight: %v", err)
	}
	got, err = f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID after weightless re-attach: %v", err)
	}
	if got.RegistryWeights[beID] != 3 {
		t.Fatalf("weight after weightless re-attach = %d, want 3 (preserved, idempotent)", got.RegistryWeights[beID])
	}
}

func TestRepository_DetachRegistryIfUnreferenced_SucceedsWithoutRoutingReferences(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "guard-detach-ok")
	beID := seedRegistry(t, f.be, gwID, "guard-detach-ok-be")
	c := validConsumer(t, gwID, "guard-detach-ok", beID)
	saveWithRegistries(t, f, c)

	detached, err := f.repo.DetachRegistryIfUnreferenced(ctx, gwID, c.ID, beID)
	if err != nil {
		t.Fatalf("DetachRegistryIfUnreferenced: %v", err)
	}
	if detached.ID != c.ID || detached.GatewayID != gwID {
		t.Fatalf("detached consumer = %+v, want id %s gateway %s", detached, c.ID, gwID)
	}
	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.RegistryIDs) != 0 {
		t.Fatalf("RegistryIDs = %v, want empty", got.RegistryIDs)
	}
}

func TestRepository_DetachRegistryIfUnreferenced_RejectsRoutingReferences(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "guard-detach-conflict")

	cases := []struct {
		name      string
		configure func(*domain.Consumer, ids.RegistryID)
	}{
		{
			name: "fallback chain",
			configure: func(c *domain.Consumer, registryID ids.RegistryID) {
				c.Fallback = &domain.Fallback{Enabled: true, Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx}, Chain: []ids.RegistryID{registryID}}
			},
		},
		{
			name: "model policies",
			configure: func(c *domain.Consumer, registryID ids.RegistryID) {
				c.ModelPolicies = domain.ModelPolicies{registryID: {Allowed: []string{"gpt-4o"}}}
			},
		},
		{
			name: "lb config members",
			configure: func(c *domain.Consumer, registryID ids.RegistryID) {
				c.ModelPolicies = domain.ModelPolicies{registryID: {Allowed: []string{"gpt-4o"}}}
				c.LBConfig = &domain.LBConfig{
					Enabled: true,
					Members: []domain.LBPoolMember{{RegistryID: registryID, Models: []string{"gpt-4o"}}},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			beID := seedRegistry(t, f.be, gwID, "guard-"+tc.name)
			c := validConsumer(t, gwID, "guard-"+tc.name, beID)
			tc.configure(c, beID)
			saveWithRegistries(t, f, c)

			_, err := f.repo.DetachRegistryIfUnreferenced(ctx, gwID, c.ID, beID)
			if !errors.Is(err, commonerrors.ErrConflict) {
				t.Fatalf("err = %v, want ErrConflict", err)
			}
			got, err := f.repo.FindByID(ctx, c.ID)
			if err != nil {
				t.Fatalf("FindByID: %v", err)
			}
			if len(got.RegistryIDs) != 1 || got.RegistryIDs[0] != beID {
				t.Fatalf("RegistryIDs = %v, want [%s]", got.RegistryIDs, beID)
			}
		})
	}
}

func TestRepository_Update_RejectsRegistryReferenceAfterDetach(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "guard-update-stale")
	beID := seedRegistry(t, f.be, gwID, "guard-update-stale-be")
	c := validConsumer(t, gwID, "guard-update-stale", beID)
	saveWithRegistries(t, f, c)
	if _, err := f.repo.DetachRegistryIfUnreferenced(ctx, gwID, c.ID, beID); err != nil {
		t.Fatalf("DetachRegistryIfUnreferenced: %v", err)
	}

	c.ModelPolicies = domain.ModelPolicies{beID: {Allowed: []string{"gpt-4o"}}}
	c.UpdatedAt = time.Now().UTC()
	err := f.repo.Update(ctx, c)
	if !errors.Is(err, registrydomain.ErrInvalidRegistryID) {
		t.Fatalf("err = %v, want ErrInvalidRegistryID", err)
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
	if err := f.repo.Delete(ctx, gwID, c.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := f.repo.FindByID(ctx, c.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete_NotFound(t *testing.T) {
	f := setupRepo(t)
	err := f.repo.Delete(context.Background(), ids.New[ids.GatewayKind](), ids.New[ids.ConsumerKind]())
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

func TestRepository_Save_PersistsRoleBindings(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool-roles")
	roleID := seedRole(t, f.roles, gwID, "role-bind")

	c, err := domain.New(domain.CreateParams{
		GatewayID:   gwID,
		Name:        "role-based-consumer",
		Type:        domain.TypeLLM,
		RoutingMode: domain.RoutingModeRoleBased,
		RoleIDs:     []ids.RoleID{roleID},
	})
	if err != nil {
		t.Fatalf("consumer domain.New: %v", err)
	}
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.RoleIDs) != 1 || got.RoleIDs[0] != roleID {
		t.Fatalf("RoleIDs = %v, want [%s]", got.RoleIDs, roleID)
	}
}

func TestRepository_DeleteBackend_CascadesConsumerBinding(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool-bd")
	beID := seedRegistry(t, f.be, gwID, "be-bd")

	c := validConsumer(t, gwID, "uses-be", beID)
	saveWithRegistries(t, f, c)

	if err := f.be.Delete(ctx, gwID, beID); err != nil {
		t.Fatalf("Delete: %v, want cascade to consumer_registry", err)
	}

	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.RegistryIDs) != 0 {
		t.Fatalf("RegistryIDs = %v, want the binding removed by cascade", got.RegistryIDs)
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

	err := f.be.Delete(ctx, gwID, fbBE)
	if !errors.Is(err, registrydomain.ErrHasDependents) {
		t.Fatalf("err = %v, want registrydomain.ErrHasDependents", err)
	}
}

func TestRepository_DeleteRegistry_IgnoresCrossGatewayFallbackConsumer(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwReg := seedGateway(t, f.gw, "gw-reg")
	gwOther := seedGateway(t, f.gw, "gw-other")
	regID := seedRegistry(t, f.be, gwReg, "victim-reg")
	otherReg := seedRegistry(t, f.be, gwOther, "other-pool")

	c := validConsumer(t, gwOther, "cross-gw-consumer", otherReg)
	c.Fallback = &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
		Budget:   domain.FallbackBudget{MaxAttempts: 3},
		Chain:    registrydomain.Registries{regID},
	}
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := f.be.Delete(ctx, gwReg, regID); err != nil {
		t.Fatalf("Delete: %v, want success (cross-gateway consumer must not block)", err)
	}
}

func TestRepository_DeleteRegistry_IgnoresInactiveConsumer(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "gw-inactive")
	poolReg := seedRegistry(t, f.be, gwID, "inactive-pool")
	regID := seedRegistry(t, f.be, gwID, "inactive-victim")

	c := validConsumer(t, gwID, "inactive-consumer", poolReg)
	c.Fallback = &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
		Budget:   domain.FallbackBudget{MaxAttempts: 3},
		Chain:    registrydomain.Registries{regID},
	}
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := f.conn.Pool.Exec(ctx, "UPDATE consumers SET active = FALSE WHERE id = $1", c.ID); err != nil {
		t.Fatalf("deactivate consumer: %v", err)
	}

	if err := f.be.Delete(ctx, gwID, regID); err != nil {
		t.Fatalf("Delete: %v, want success (inactive consumer must not block)", err)
	}
}

func TestRepository_DeleteRegistry_BlockedByActiveSameGatewayConsumer(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "gw-block")
	poolReg := seedRegistry(t, f.be, gwID, "block-pool")
	regID := seedRegistry(t, f.be, gwID, "block-victim")

	c := validConsumer(t, gwID, "active-consumer", poolReg)
	c.Fallback = &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
		Budget:   domain.FallbackBudget{MaxAttempts: 3},
		Chain:    registrydomain.Registries{regID},
	}
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	err := f.be.Delete(ctx, gwID, regID)
	if !errors.Is(err, registrydomain.ErrHasDependents) {
		t.Fatalf("err = %v, want registrydomain.ErrHasDependents", err)
	}
}
