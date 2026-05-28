package backend_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	_ "github.com/NeuralTrust/AgentGateway/pkg/infra/database/migrations"
	repo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/backend"
	gatewayrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/gateway"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setupRepo(t *testing.T) (*repo.Repository, *gatewayrepo.Repository, *database.Connection) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping backend repository integration test")
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
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE backends, gateways CASCADE")
		pool.Close()
	})

	return repo.NewRepository(conn), gatewayrepo.NewRepository(conn), conn
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

func validBackend(t *testing.T, gwID uuid.UUID, name string) *domain.Backend {
	t.Helper()
	b, err := domain.New(domain.CreateParams{
		GatewayID: gwID,
		Name:      name,
		Algorithm: domain.AlgorithmRoundRobin,
		Targets: domain.Targets{
			{
				Provider: "openai",
				Auth:     domain.NewAPIKeyAuth("sk-test"),
			},
		},
	})
	if err != nil {
		t.Fatalf("backend domain.New: %v", err)
	}
	return b
}

func TestRepository_SaveAndFindByID(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pool")

	b := validBackend(t, gwID, "openai-pool")
	b.EmbeddingConfig = &domain.EmbeddingConfig{
		Provider: "openai",
		Model:    "text-embedding-3-small",
		Auth:     &domain.APIKeyAuth{APIKey: "sk-e"},
	}
	b.Algorithm = domain.AlgorithmSemantic
	b.Targets[0].Description = "primary"

	if err := r.Save(ctx, b); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindByID(ctx, b.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != b.ID || got.GatewayID != gwID || got.Name != "openai-pool" {
		t.Fatalf("FindByID returned %+v", got)
	}
	if got.Algorithm != domain.AlgorithmSemantic {
		t.Fatalf("Algorithm = %q, want %q", got.Algorithm, domain.AlgorithmSemantic)
	}
	if len(got.Targets) != 1 || got.Targets[0].Provider != "openai" {
		t.Fatalf("Targets round-trip lost data: %+v", got.Targets)
	}
	if got.EmbeddingConfig == nil || got.EmbeddingConfig.Model != "text-embedding-3-small" {
		t.Fatalf("EmbeddingConfig round-trip lost data: %+v", got.EmbeddingConfig)
	}
}

func TestRepository_SaveAndFindByID_NullableEmbedding(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pool2")

	b := validBackend(t, gwID, "naked")
	if err := r.Save(ctx, b); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := r.FindByID(ctx, b.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.EmbeddingConfig != nil {
		t.Fatalf("EmbeddingConfig should be nil, got %+v", got.EmbeddingConfig)
	}
}

func TestRepository_FindByID_NotFound(t *testing.T) {
	r, _, _ := setupRepo(t)
	_, err := r.FindByID(context.Background(), uuid.New())
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
	gwID := seedGateway(t, gw, "pool3")

	b1 := validBackend(t, gwID, "dupe")
	if err := r.Save(ctx, b1); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	b2 := validBackend(t, gwID, "dupe")
	err := r.Save(ctx, b2)
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestRepository_Save_InvalidGatewayID(t *testing.T) {
	r, _, _ := setupRepo(t)
	ctx := context.Background()
	orphanGW := uuid.New()
	b := validBackend(t, orphanGW, "orphan")
	err := r.Save(ctx, b)
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestRepository_Update(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "poolu")

	b := validBackend(t, gwID, "alpha")
	if err := r.Save(ctx, b); err != nil {
		t.Fatalf("Save: %v", err)
	}

	b.Name = "alpha-renamed"
	b.Algorithm = domain.AlgorithmRandom
	b.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, b); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := r.FindByID(ctx, b.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if got.Name != "alpha-renamed" || got.Algorithm != domain.AlgorithmRandom {
		t.Fatalf("Update did not persist: %+v", got)
	}
}

func TestRepository_Update_NotFound(t *testing.T) {
	r, gw, _ := setupRepo(t)
	gwID := seedGateway(t, gw, "poolu2")
	b := validBackend(t, gwID, "ghost")
	err := r.Update(context.Background(), b)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "poold")

	b := validBackend(t, gwID, "victim")
	if err := r.Save(ctx, b); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := r.Delete(ctx, b.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.FindByID(ctx, b.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete_NotFound(t *testing.T) {
	r, _, _ := setupRepo(t)
	err := r.Delete(context.Background(), uuid.New())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_List_FilterByGatewayAndName(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, gw, "gw1")
	gw2 := seedGateway(t, gw, "gw2")

	mustSave := func(b *domain.Backend) {
		if err := r.Save(ctx, b); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	mustSave(validBackend(t, gw1, "openai-prod"))
	mustSave(validBackend(t, gw1, "openai-staging"))
	mustSave(validBackend(t, gw2, "anthropic-prod"))

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
