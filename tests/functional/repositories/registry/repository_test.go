//go:build functional

package registry_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	gatewayrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testSecretKey = "functional-test-secret-0123456789abcdef"

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
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE registries, gateways CASCADE")
		pool.Close()
	})

	cipher, err := crypto.NewCipher(testSecretKey)
	if err != nil {
		pool.Close()
		t.Fatalf("new cipher: %v", err)
	}

	appender := outboxrepo.NewRepository(conn)
	return repo.NewRepository(conn, cipher, appender), gatewayrepo.NewRepository(conn, appender), conn
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

func validRegistry(t *testing.T, gwID ids.GatewayID, name string) *domain.Registry {
	t.Helper()
	b, err := domain.NewLLMRegistry(gwID, name, "", &domain.LLMTarget{
		Provider: "openai",
		Auth:     domain.NewAPIKeyAuth("sk-test"),
	})
	if err != nil {
		t.Fatalf("backend domain.NewLLMRegistry: %v", err)
	}
	return b
}

func TestRepository_SaveAndFindByID(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pool")

	b := validRegistry(t, gwID, "openai-pool")
	b.Description = "primary"
	b.LLMTarget.ProviderOptions = map[string]any{"base_url": "https://api.openai.com"}

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
	if got.Provider() != "openai" {
		t.Fatalf("Provider = %q, want openai", got.Provider())
	}
	if got.Description != "primary" {
		t.Fatalf("Description = %q, want primary", got.Description)
	}
	if got.ProviderOptions()["base_url"] != "https://api.openai.com" {
		t.Fatalf("ProviderOptions round-trip lost data: %+v", got.ProviderOptions())
	}
	if got.Auth() == nil || got.Auth().APIKey == nil {
		t.Fatalf("Auth round-trip lost data: %+v", got.Auth())
	}
}

func TestRepository_SaveAndFindByID_NullableProviderOptions(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pool2")

	b := validRegistry(t, gwID, "naked")
	if err := r.Save(ctx, b); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := r.FindByID(ctx, b.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.ProviderOptions()) != 0 {
		t.Fatalf("ProviderOptions should be empty, got %+v", got.ProviderOptions())
	}
}

func TestRepository_FindByID_NotFound(t *testing.T) {
	r, _, _ := setupRepo(t)
	_, err := r.FindByID(context.Background(), ids.New[ids.RegistryKind]())
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

	b1 := validRegistry(t, gwID, "dupe")
	if err := r.Save(ctx, b1); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	b2 := validRegistry(t, gwID, "dupe")
	err := r.Save(ctx, b2)
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestRepository_Save_InvalidGatewayID(t *testing.T) {
	r, _, _ := setupRepo(t)
	ctx := context.Background()
	orphanGW := ids.New[ids.GatewayKind]()
	b := validRegistry(t, orphanGW, "orphan")
	err := r.Save(ctx, b)
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestRepository_Update(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "poolu")

	b := validRegistry(t, gwID, "alpha")
	if err := r.Save(ctx, b); err != nil {
		t.Fatalf("Save: %v", err)
	}

	b.Name = "alpha-renamed"
	b.LLMTarget.Provider = "anthropic"
	b.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, b); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := r.FindByID(ctx, b.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if got.Name != "alpha-renamed" || got.Provider() != "anthropic" {
		t.Fatalf("Update did not persist: %+v", got)
	}
}

func TestRepository_Update_NotFound(t *testing.T) {
	r, gw, _ := setupRepo(t)
	gwID := seedGateway(t, gw, "poolu2")
	b := validRegistry(t, gwID, "ghost")
	err := r.Update(context.Background(), b)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "poold")

	b := validRegistry(t, gwID, "victim")
	if err := r.Save(ctx, b); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := r.Delete(ctx, gwID, b.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.FindByID(ctx, b.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete_NotFound(t *testing.T) {
	r, _, _ := setupRepo(t)
	err := r.Delete(context.Background(), ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_List_FilterByGatewayAndName(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, gw, "gw1")
	gw2 := seedGateway(t, gw, "gw2")

	mustSave := func(b *domain.Registry) {
		if err := r.Save(ctx, b); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	mustSave(validRegistry(t, gw1, "openai-prod"))
	mustSave(validRegistry(t, gw1, "openai-staging"))
	mustSave(validRegistry(t, gw2, "anthropic-prod"))

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
