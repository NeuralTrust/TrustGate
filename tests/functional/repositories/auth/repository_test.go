//go:build functional

package auth_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	_ "github.com/NeuralTrust/AgentGateway/pkg/infra/database/migrations"
	repo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/auth"
	gatewayrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/gateway"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setupRepo(t *testing.T) (*repo.Repository, *gatewayrepo.Repository) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping auth repository integration test")
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
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE auths, gateways CASCADE")
		pool.Close()
	})

	return repo.NewRepository(conn), gatewayrepo.NewRepository(conn)
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

func validAuth(t *testing.T, gwID ids.GatewayID, name string) *domain.Auth {
	t.Helper()
	a, err := domain.NewAPIKeyAuth(gwID, name, true)
	if err != nil {
		t.Fatalf("auth domain.NewAPIKeyAuth: %v", err)
	}
	return a
}

func TestRepository_SaveAndFindByID(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw")

	a := validAuth(t, gwID, "client-key")
	if err := r.Save(ctx, a); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != a.ID || got.GatewayID != gwID || got.Name != "client-key" {
		t.Fatalf("FindByID returned %+v", got)
	}
	if got.Type != domain.TypeAPIKey {
		t.Fatalf("type round-trip lost data: %+v", got)
	}
	if got.KeyHash == "" || got.KeyHash != a.KeyHash {
		t.Fatalf("key_hash round-trip lost data: got %q want %q", got.KeyHash, a.KeyHash)
	}
}

func TestRepository_FindByAPIKeyHash(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-hash")

	a := validAuth(t, gwID, "lookup-key")
	if a.RawKey == "" {
		t.Fatalf("generated auth missing raw key for assertion")
	}
	if err := r.Save(ctx, a); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindByAPIKeyHash(ctx, domain.HashAPIKey(a.RawKey))
	if err != nil {
		t.Fatalf("FindByAPIKeyHash: %v", err)
	}
	if got.ID != a.ID || got.Type != domain.TypeAPIKey {
		t.Fatalf("FindByAPIKeyHash returned %+v", got)
	}
}

func TestRepository_FindByAPIKeyHash_NotFound(t *testing.T) {
	r, _ := setupRepo(t)
	_, err := r.FindByAPIKeyHash(context.Background(), domain.HashAPIKey("ag_nonexistent"))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_FindByID_NotFound(t *testing.T) {
	r, _ := setupRepo(t)
	_, err := r.FindByID(context.Background(), ids.New[ids.AuthKind]())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("err = %v, want it to wrap commonerrors.ErrNotFound", err)
	}
}

func TestRepository_Save_DuplicateNameForSameGateway(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-dup")

	if err := r.Save(ctx, validAuth(t, gwID, "dupe")); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	err := r.Save(ctx, validAuth(t, gwID, "dupe"))
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestRepository_Save_InvalidGatewayID(t *testing.T) {
	r, _ := setupRepo(t)
	err := r.Save(context.Background(), validAuth(t, ids.New[ids.GatewayKind](), "orphan"))
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestRepository_Update(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-upd")

	a := validAuth(t, gwID, "alpha")
	if err := r.Save(ctx, a); err != nil {
		t.Fatalf("Save: %v", err)
	}

	a.Name = "alpha-renamed"
	a.Type = domain.TypeOAuth2
	a.Config = domain.Config{OAuth2: &domain.OAuth2Config{
		Issuer:  "https://issuer",
		JWKSURL: "https://issuer/.well-known/jwks.json",
	}}
	a.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, a); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := r.FindByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if got.Name != "alpha-renamed" || got.Type != domain.TypeOAuth2 {
		t.Fatalf("update not persisted: %+v", got)
	}
	if got.Config.OAuth2 == nil || got.Config.OAuth2.Issuer != "https://issuer" {
		t.Fatalf("oauth2 config not persisted: %+v", got.Config)
	}
}

func TestRepository_Update_NotFound(t *testing.T) {
	r, gw := setupRepo(t)
	gwID := seedGateway(t, gw, "agw-upd2")
	err := r.Update(context.Background(), validAuth(t, gwID, "ghost"))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-del")

	a := validAuth(t, gwID, "victim")
	if err := r.Save(ctx, a); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := r.Delete(ctx, a.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.FindByID(ctx, a.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_FindByIDs(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-ids")

	a1 := validAuth(t, gwID, "k1")
	a2 := validAuth(t, gwID, "k2")
	for _, a := range []*domain.Auth{a1, a2} {
		if err := r.Save(ctx, a); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	found, err := r.FindByIDs(ctx, gwID, []ids.AuthID{a1.ID, a2.ID})
	if err != nil {
		t.Fatalf("FindByIDs: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("FindByIDs len = %d, want 2", len(found))
	}
}

func TestRepository_List_FilterByGatewayAndName(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, gw, "agw-l1")
	gw2 := seedGateway(t, gw, "agw-l2")

	mustSave := func(a *domain.Auth) {
		if err := r.Save(ctx, a); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	mustSave(validAuth(t, gw1, "prod-key"))
	mustSave(validAuth(t, gw1, "staging-key"))
	mustSave(validAuth(t, gw2, "other-key"))

	items, total, err := r.List(ctx, domain.ListFilter{GatewayID: gw1, Page: 1, Size: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("List(gw1) total=%d len=%d, want 2/2", total, len(items))
	}

	items, total, err = r.List(ctx, domain.ListFilter{NameContains: "other", Page: 1, Size: 10})
	if err != nil {
		t.Fatalf("List name: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Name != "other-key" {
		t.Fatalf("List(name) returned %+v", items)
	}
}
