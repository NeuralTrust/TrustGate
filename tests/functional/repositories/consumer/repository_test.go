package consumer_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	_ "github.com/NeuralTrust/AgentGateway/pkg/infra/database/migrations"
	backendrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/backend"
	repo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/consumer"
	gatewayrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/gateway"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixture struct {
	repo *repo.Repository
	gw   *gatewayrepo.Repository
	be   *backendrepo.Repository
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
			"TRUNCATE TABLE consumer_backend, consumers, backends, gateways CASCADE")
		pool.Close()
	})

	return fixture{
		repo: repo.NewRepository(conn),
		gw:   gatewayrepo.NewRepository(conn),
		be:   backendrepo.NewRepository(conn),
	}
}

func seedGateway(t *testing.T, gw *gatewayrepo.Repository, name string) uuid.UUID {
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

func seedBackend(t *testing.T, be *backendrepo.Repository, gwID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	b, err := backenddomain.NewBackend(gwID, name, backenddomain.AlgorithmRoundRobin, backenddomain.Targets{
		{Provider: "openai", Auth: backenddomain.NewAPIKeyAuth("sk-test")},
	}, nil, nil)
	if err != nil {
		t.Fatalf("backend domain.NewBackend: %v", err)
	}
	if err := be.Save(context.Background(), b); err != nil {
		t.Fatalf("backend Save: %v", err)
	}
	return b.ID
}

func validConsumer(t *testing.T, gwID uuid.UUID, name string, beIDs ...uuid.UUID) *domain.Consumer {
	t.Helper()
	c, err := domain.New(domain.CreateParams{
		GatewayID:  gwID,
		Name:       name,
		Type:       domain.TypeLLM,
		BackendIDs: beIDs,
	})
	if err != nil {
		t.Fatalf("consumer domain.New: %v", err)
	}
	return c
}

func TestRepository_SaveAndFindByID(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool")
	beID := seedBackend(t, f.be, gwID, "be1")

	c := validConsumer(t, gwID, "openai-chat", beID)
	c.Headers = map[string]string{"X-Tenant": "acme"}

	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

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
	if len(got.BackendIDs) != 1 || got.BackendIDs[0] != beID {
		t.Fatalf("BackendIDs = %v, want [%s]", got.BackendIDs, beID)
	}
	if got.Headers["X-Tenant"] != "acme" {
		t.Fatalf("Headers lost data: %+v", got.Headers)
	}
}

func TestRepository_FindByID_NotFound(t *testing.T) {
	f := setupRepo(t)
	_, err := f.repo.FindByID(context.Background(), uuid.New())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Save_DuplicateNameForSameGateway(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool3")
	beID := seedBackend(t, f.be, gwID, "be3")

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

func TestRepository_Save_SameNameDifferentGatewaysAllowed(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, f.gw, "g-a")
	gw2 := seedGateway(t, f.gw, "g-b")
	be1 := seedBackend(t, f.be, gw1, "be-a")
	be2 := seedBackend(t, f.be, gw2, "be-b")

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
	orphanGW := uuid.New()
	c := validConsumer(t, orphanGW, "orphan", uuid.New())
	err := f.repo.Save(ctx, c)
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestRepository_Save_InvalidBackendID(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "pool-be")
	ghostBE := uuid.New()
	c := validConsumer(t, gwID, "with-ghost", ghostBE)
	err := f.repo.Save(ctx, c)
	if !errors.Is(err, domain.ErrInvalidBackendID) {
		t.Fatalf("err = %v, want ErrInvalidBackendID", err)
	}
}

func TestRepository_Update_RebindsBackends(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "rebind")
	be1 := seedBackend(t, f.be, gwID, "be-x")
	be2 := seedBackend(t, f.be, gwID, "be-y")
	be3 := seedBackend(t, f.be, gwID, "be-z")

	c := validConsumer(t, gwID, "rb", be1, be2)
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	c.BackendIDs = []uuid.UUID{be2, be3}
	c.Name = "rb-v2"
	c.UpdatedAt = time.Now().UTC()
	if err := f.repo.Update(ctx, c); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Name != "rb-v2" {
		t.Fatalf("Name = %q", got.Name)
	}
	if len(got.BackendIDs) != 2 {
		t.Fatalf("BackendIDs len = %d, want 2", len(got.BackendIDs))
	}
	have := map[uuid.UUID]bool{got.BackendIDs[0]: true, got.BackendIDs[1]: true}
	if !have[be2] || !have[be3] {
		t.Fatalf("BackendIDs = %v, want [%s,%s]", got.BackendIDs, be2, be3)
	}
}

func TestRepository_Update_NotFound(t *testing.T) {
	f := setupRepo(t)
	gwID := seedGateway(t, f.gw, "pool-u2")
	beID := seedBackend(t, f.be, gwID, "be-u2")
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
	beID := seedBackend(t, f.be, gwID, "be-d")
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
	err := f.repo.Delete(context.Background(), uuid.New())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_List_FilterByGatewayAndName(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, f.gw, "gw-l1")
	gw2 := seedGateway(t, f.gw, "gw-l2")
	be1 := seedBackend(t, f.be, gw1, "be-l1")
	be2 := seedBackend(t, f.be, gw2, "be-l2")

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
	beID := seedBackend(t, f.be, gwID, "be-bd")

	if err := f.repo.Save(ctx, validConsumer(t, gwID, "uses-be", beID)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	err := f.be.Delete(ctx, beID)
	if !errors.Is(err, backenddomain.ErrHasDependents) {
		t.Fatalf("err = %v, want backenddomain.ErrHasDependents", err)
	}
}
