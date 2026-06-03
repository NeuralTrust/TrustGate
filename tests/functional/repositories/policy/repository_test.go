//go:build functional

package policy_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	_ "github.com/NeuralTrust/AgentGateway/pkg/infra/database/migrations"
	gatewayrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/gateway"
	repo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/policy"
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
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE policies, registries, gateways CASCADE")
		pool.Close()
	})

	return repo.NewRepository(conn), gatewayrepo.NewRepository(conn), conn
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
	p, err := domain.NewPolicy(gwID, name, domain.Plugins{
		{
			Name:     "rate_limiter",
			Enabled:  true,
			Stage:    domain.StagePreRequest,
			Priority: 0,
			Settings: map[string]interface{}{"limit": 100},
		},
	})
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
	if len(got.Plugins) != 1 || got.Plugins[0].Name != "rate_limiter" {
		t.Fatalf("Plugins round-trip lost data: %+v", got.Plugins)
	}
	if got.Plugins[0].Stage != domain.StagePreRequest {
		t.Fatalf("Plugin stage = %q, want %q", got.Plugins[0].Stage, domain.StagePreRequest)
	}
}

func TestRepository_SaveAndFindByID_EmptyPlugins(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-empty")

	p, err := domain.NewPolicy(gwID, "empty", nil)
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
	if got.Plugins == nil {
		t.Fatal("Plugins should be a non-nil empty slice")
	}
	if len(got.Plugins) != 0 {
		t.Fatalf("len = %d, want 0", len(got.Plugins))
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
	p.Plugins = domain.Plugins{
		{Name: "cors", Enabled: false, Stage: domain.StagePostResponse},
	}
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
	if len(got.Plugins) != 1 || got.Plugins[0].Name != "cors" {
		t.Fatalf("Plugins not persisted: %+v", got.Plugins)
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
