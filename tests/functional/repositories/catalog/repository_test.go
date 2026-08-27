//go:build functional

package catalog_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/catalog"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setupRepo(t *testing.T) (*repo.Repository, *database.Connection) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping catalog repository integration test")
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
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE models_catalog, providers_catalog CASCADE")
		pool.Close()
	})

	return repo.NewRepository(conn, outboxrepo.NewRepository(conn)), conn
}

func seedProvider(t *testing.T, r *repo.Repository, code string) ids.ProviderID {
	t.Helper()
	p := &domain.Provider{
		ID:          ids.New[ids.ProviderKind](),
		Code:        code,
		DisplayName: code,
		WireFormat:  "openai",
		Source:      "seed",
	}
	if err := r.UpsertProvider(context.Background(), p); err != nil {
		t.Fatalf("UpsertProvider: %v", err)
	}
	return p.ID
}

// seedLegacyModel writes a row the way an ADD COLUMN leaves one behind: every
// optional column NULL. UpsertModel cannot produce this — it sends Go values,
// so it writes ” and 0 — which is exactly why a bug of this shape survives a
// test suite that only ever seeds through the domain.
func seedLegacyModel(t *testing.T, conn *database.Connection, providerID ids.ProviderID, slug string) {
	t.Helper()
	const insert = `
		INSERT INTO models_catalog (
			id, provider_id, slug, external_id, display_name, context_window, max_output,
			input_price, output_price, capabilities, enabled, source, created_at, updated_at
		) VALUES ($1, $2, $3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, TRUE, 'legacy', $4, $4)`
	now := time.Now().UTC()
	if _, err := conn.Pool.Exec(
		context.Background(), insert, ids.New[ids.ModelKind](), providerID, slug, now,
	); err != nil {
		t.Fatalf("seed legacy model: %v", err)
	}
}

// A NULL in any optional column used to fail the scan and collapse to a 500 on
// /v1/models-catalog, taking the whole provider's listing with it.
func TestRepository_ListModelsByProviderCode_LegacyNullColumns(t *testing.T) {
	r, conn := setupRepo(t)
	ctx := context.Background()
	providerID := seedProvider(t, r, "openai")
	seedLegacyModel(t, conn, providerID, "legacy-model")

	models, err := r.ListModelsByProviderCode(ctx, "openai")
	if err != nil {
		t.Fatalf("ListModelsByProviderCode: %v", err)
	}
	if len(models) != 1 {
		t.Fatalf("models = %d, want 1", len(models))
	}
	got := models[0]
	if got.Slug != "legacy-model" {
		t.Fatalf("Slug = %q, want legacy-model", got.Slug)
	}
	if got.ExternalID != "" || got.DisplayName != "" {
		t.Fatalf("NULL text columns did not zero: ExternalID=%q DisplayName=%q", got.ExternalID, got.DisplayName)
	}
	if got.ContextWindow != 0 || got.MaxOutput != 0 {
		t.Fatalf("NULL int columns did not zero: ContextWindow=%d MaxOutput=%d", got.ContextWindow, got.MaxOutput)
	}
	if got.InputPrice != "" || got.OutputPrice != "" {
		t.Fatalf("NULL price columns did not zero: InputPrice=%q OutputPrice=%q", got.InputPrice, got.OutputPrice)
	}
	// The migration closed these, so the row must have been defaulted, not NULL.
	if got.CacheReadPrice != "" || got.CacheWritePrice != "" {
		t.Fatalf("cache prices = (%q, %q), want empty", got.CacheReadPrice, got.CacheWritePrice)
	}
}

// FindModel shares the projection, and it is the one pricing calls per request.
func TestRepository_FindModel_LegacyNullColumns(t *testing.T) {
	r, conn := setupRepo(t)
	ctx := context.Background()
	providerID := seedProvider(t, r, "anthropic")
	seedLegacyModel(t, conn, providerID, "legacy-model")

	got, err := r.FindModel(ctx, "anthropic", "legacy-model")
	if err != nil {
		t.Fatalf("FindModel: %v", err)
	}
	if got.Slug != "legacy-model" || got.InputPrice != "" || got.MaxOutput != 0 {
		t.Fatalf("FindModel returned %+v", got)
	}

	if _, err := r.FindModel(ctx, "anthropic", "absent"); !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("FindModel(absent) error = %v, want ErrNotFound", err)
	}
}

// A model written through the domain must round-trip whole, cache prices
// included — the columns whose arrival caused the regression.
func TestRepository_UpsertModel_RoundTrip(t *testing.T) {
	r, _ := setupRepo(t)
	ctx := context.Background()
	providerID := seedProvider(t, r, "mistral")

	release := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	want := &domain.Model{
		ProviderID:       providerID,
		Slug:             "mistral-large",
		ExternalID:       "mistral-large-latest",
		DisplayName:      "Mistral Large",
		ContextWindow:    128000,
		MaxOutput:        8192,
		InputPrice:       "2.00",
		OutputPrice:      "6.00",
		CacheReadPrice:   "0.25",
		CacheWritePrice:  "0.50",
		Capabilities:     map[string]any{"tools": true},
		Enabled:          true,
		Source:           "models.dev",
		ReleaseDate:      &release,
		InputModalities:  []string{"text"},
		OutputModalities: []string{"text"},
	}
	if err := r.UpsertModel(ctx, want); err != nil {
		t.Fatalf("UpsertModel: %v", err)
	}

	got, err := r.FindModel(ctx, "mistral", "mistral-large")
	if err != nil {
		t.Fatalf("FindModel: %v", err)
	}
	if got.CacheReadPrice != "0.25" || got.CacheWritePrice != "0.50" {
		t.Fatalf("cache prices = (%q, %q), want (0.25, 0.50)", got.CacheReadPrice, got.CacheWritePrice)
	}
	if got.InputPrice != "2.00" || got.OutputPrice != "6.00" {
		t.Fatalf("prices = (%q, %q), want (2.00, 6.00)", got.InputPrice, got.OutputPrice)
	}
	if got.ContextWindow != 128000 || got.MaxOutput != 8192 {
		t.Fatalf("limits = (%d, %d), want (128000, 8192)", got.ContextWindow, got.MaxOutput)
	}
	if got.ReleaseDate == nil || !got.ReleaseDate.Equal(release) {
		t.Fatalf("ReleaseDate = %v, want %v", got.ReleaseDate, release)
	}
}
