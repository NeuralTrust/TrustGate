//go:build functional

package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/jackc/pgx/v5/pgxpool"
)

// setupRepo opens a pgx pool against PG_TEST_URL, applies all
// registered migrations, and registers a cleanup that truncates the
// gateways table between tests. When PG_TEST_URL is not set the test
// is skipped — see AGENT.md §9.
func setupRepo(t *testing.T) (*repo.Repository, *database.Connection) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping gateway repository integration test")
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
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE gateways CASCADE")
		pool.Close()
	})

	return repo.NewRepository(conn, outboxrepo.NewRepository(conn)), conn
}

func TestRepository_SaveAndFindByID(t *testing.T) {
	r, _ := setupRepo(t)
	ctx := context.Background()

	g, err := domain.New("alpha")
	if err != nil {
		t.Fatalf("domain.New: %v", err)
	}
	g.Telemetry = &telemetry.Telemetry{
		ExtraParams: map[string]string{"env": "prod"},
	}
	g.ClientTLSConfig = domain.ClientTLSConfig{
		"api.example.com": json.RawMessage(`{"insecure":false}`),
	}
	if err := r.Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindByID(ctx, g.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != g.ID || got.Slug != "alpha" || got.Status != "active" {
		t.Fatalf("FindByID returned %+v", got)
	}
	if got.Slug != "alpha" {
		t.Fatalf("Slug = %q, want alpha", got.Slug)
	}
	if got.Telemetry == nil || got.Telemetry.ExtraParams["env"] != "prod" {
		t.Fatalf("Telemetry round-trip lost data: %+v", got.Telemetry)
	}
	if len(got.ClientTLSConfig) != 1 {
		t.Fatalf("ClientTLSConfig round-trip lost entries: %+v", got.ClientTLSConfig)
	}
	var decoded map[string]bool
	if err := json.Unmarshal(got.ClientTLSConfig["api.example.com"], &decoded); err != nil {
		t.Fatalf("ClientTLSConfig entry not valid JSON: %v", err)
	}
	if decoded["insecure"] != false {
		t.Fatalf("ClientTLSConfig round-trip mutated payload: %+v", decoded)
	}
}

func TestRepository_SaveAndFindByID_NullableJSONB(t *testing.T) {
	r, _ := setupRepo(t)
	ctx := context.Background()

	g, err := domain.New("naked")
	if err != nil {
		t.Fatalf("domain.New: %v", err)
	}
	if err := r.Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindByID(ctx, g.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Telemetry != nil {
		t.Fatalf("Telemetry should be nil for NULL column, got %+v", got.Telemetry)
	}
	if got.ClientTLSConfig != nil {
		t.Fatalf("ClientTLSConfig should be nil for NULL column, got %+v", got.ClientTLSConfig)
	}
}

func TestRepository_FindBySlug(t *testing.T) {
	r, _ := setupRepo(t)
	ctx := context.Background()

	g, err := domain.New("acme")
	if err != nil {
		t.Fatalf("domain.New: %v", err)
	}
	if err := r.Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindBySlug(ctx, "acme")
	if err != nil {
		t.Fatalf("FindBySlug: %v", err)
	}
	if got.ID != g.ID {
		t.Fatalf("FindBySlug returned gateway %s, want %s", got.ID, g.ID)
	}
}

func TestRepository_FindByID_NotFound(t *testing.T) {
	r, _ := setupRepo(t)
	_, err := r.FindByID(context.Background(), ids.New[ids.GatewayKind]())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("err = %v, want it to wrap commonerrors.ErrNotFound", err)
	}
}

func TestRepository_Save_Duplicate(t *testing.T) {
	r, _ := setupRepo(t)
	ctx := context.Background()

	g1, _ := domain.New("dupe")
	if err := r.Save(ctx, g1); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	g2, _ := domain.New("dupe")
	err := r.Save(ctx, g2)
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestRepository_Save_DuplicateSlug(t *testing.T) {
	r, _ := setupRepo(t)
	ctx := context.Background()

	g1, _ := domain.New("shared")
	if err := r.Save(ctx, g1); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	g2, _ := domain.New("shared")
	err := r.Save(ctx, g2)
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestRepository_Update(t *testing.T) {
	r, _ := setupRepo(t)
	ctx := context.Background()

	g, _ := domain.New("alpha")
	if err := r.Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}

	g.Slug = "alpha-renamed"
	g.Status = "paused"
	g.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, g); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := r.FindByID(ctx, g.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if got.Slug != "alpha-renamed" || got.Status != "paused" {
		t.Fatalf("Update did not persist: %+v", got)
	}
}

func TestRepository_Update_NotFound(t *testing.T) {
	r, _ := setupRepo(t)
	g, _ := domain.New("ghost")
	err := r.Update(context.Background(), g)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete(t *testing.T) {
	r, _ := setupRepo(t)
	ctx := context.Background()

	g, _ := domain.New("victim")
	if err := r.Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := r.Delete(ctx, g.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.FindByID(ctx, g.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("FindByID after delete err = %v, want ErrNotFound", err)
	}
	if err := r.Delete(ctx, g.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second Delete err = %v, want ErrNotFound", err)
	}
}

func TestRepository_List(t *testing.T) {
	r, _ := setupRepo(t)
	ctx := context.Background()

	for _, slug := range []string{"alpha", "alphabet", "beta", "gamma", "delta"} {
		g, _ := domain.New(slug)
		if err := r.Save(ctx, g); err != nil {
			t.Fatalf("Save %s: %v", slug, err)
		}
	}

	// total == 5, no filter, page 1 size 2
	items, total, err := r.List(ctx, domain.ListFilter{Page: 1, Size: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 5 {
		t.Fatalf("total = %d, want 5", total)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}

	// total == 2 matching "alph", regardless of page/size
	items, total, err = r.List(ctx, domain.ListFilter{SlugContains: "alph", Page: 1, Size: 20})
	if err != nil {
		t.Fatalf("List with filter: %v", err)
	}
	if total != 2 {
		t.Fatalf("filtered total = %d, want 2", total)
	}
	gotSlugs := make([]string, 0, len(items))
	for _, it := range items {
		gotSlugs = append(gotSlugs, it.Slug)
	}
	joined := strings.Join(gotSlugs, ",")
	if !strings.Contains(joined, "alpha") || !strings.Contains(joined, "alphabet") {
		t.Fatalf("filtered items = %v, expected alpha + alphabet", gotSlugs)
	}

	// case-insensitive
	_, totalUpper, err := r.List(ctx, domain.ListFilter{SlugContains: "ALPH"})
	if err != nil {
		t.Fatalf("List case-insensitive: %v", err)
	}
	if totalUpper != 2 {
		t.Fatalf("case-insensitive total = %d, want 2", totalUpper)
	}
}
