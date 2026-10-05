//go:build functional

package configsnapshotlkg_test

import (
	"context"
	"os"
	"sort"
	"testing"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsnapshotlkg"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setup(t *testing.T) *repo.Repository {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping config snapshot LKG repository integration test")
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
	if err := database.NewMigrationsManager(pool).ApplyPending(ctx); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE config_snapshot_lkg"); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE config_snapshot_lkg")
		pool.Close()
	})
	return repo.NewRepository(&database.Connection{Pool: pool})
}

func rec(scope, version string, at time.Time, payload string) appsnapshot.LKGRecord {
	return appsnapshot.LKGRecord{Scope: scope, Version: version, CompiledAt: at, KeyID: "key-1", Payload: []byte(payload)}
}

func byScope(t *testing.T, r *repo.Repository) map[string]appsnapshot.LKGRecord {
	t.Helper()
	rows, err := r.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out := map[string]appsnapshot.LKGRecord{}
	for _, row := range rows {
		out[row.Scope] = row
	}
	return out
}

func TestRepository_SaveRoundTripsAndCompiledAtGuardsTheUpsert(t *testing.T) {
	r := setup(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	written, err := r.Save(ctx, rec("", "v1", t0, "first"))
	if err != nil || !written {
		t.Fatalf("first Save = %v, %v; want written", written, err)
	}
	got := byScope(t, r)[""]
	if got.Version != "v1" || string(got.Payload) != "first" || got.KeyID != "key-1" || !got.CompiledAt.Equal(t0) {
		t.Fatalf("round trip lost data: %+v", got)
	}

	written, err = r.Save(ctx, rec("", "v2", t0.Add(time.Minute), "newer"))
	if err != nil || !written {
		t.Fatalf("a newer compile must overwrite: %v, %v", written, err)
	}

	// An older compile from a slow replica arrives last and must not win.
	written, err = r.Save(ctx, rec("", "v0", t0.Add(-time.Hour), "older"))
	if err != nil {
		t.Fatalf("Save older: %v", err)
	}
	if written {
		t.Fatal("an older compile must report not written")
	}
	// An equal timestamp is not newer either.
	if written, _ = r.Save(ctx, rec("", "vx", t0.Add(time.Minute), "same-instant")); written {
		t.Fatal("an equal compiled_at must not overwrite")
	}
	if got := byScope(t, r)[""]; got.Version != "v2" || string(got.Payload) != "newer" {
		t.Fatalf("the newer row was overwritten by an older compile: %+v", got)
	}
}

func TestRepository_DeleteVanishedKeepsListedAndNewerScopes(t *testing.T) {
	r := setup(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, s := range []struct {
		scope string
		at    time.Time
	}{{"", t0}, {"kept", t0}, {"gone", t0}, {"created-meanwhile", t0.Add(time.Minute)}} {
		if _, err := r.Save(ctx, rec(s.scope, "v", s.at, "p")); err != nil {
			t.Fatalf("Save %q: %v", s.scope, err)
		}
	}

	if err := r.DeleteVanished(ctx, []string{"", "kept"}, t0); err != nil {
		t.Fatalf("DeleteVanished: %v", err)
	}
	var left []string
	for scope := range byScope(t, r) {
		left = append(left, scope)
	}
	sort.Strings(left)
	want := []string{"", "created-meanwhile", "kept"}
	if len(left) != len(want) {
		t.Fatalf("scopes left = %v, want %v", left, want)
	}
	for i := range want {
		if left[i] != want[i] {
			t.Fatalf("scopes left = %v, want %v", left, want)
		}
	}

	// An empty keep list must delete by the same rule rather than error.
	if err := r.DeleteVanished(ctx, nil, t0.Add(time.Hour)); err != nil {
		t.Fatalf("DeleteVanished(nil): %v", err)
	}
	if n := len(byScope(t, r)); n != 0 {
		t.Fatalf("%d rows left after deleting everything not newer", n)
	}
}

func TestRepository_TouchAdvancesOnlyMatchingVersionsAndNeverRewindsOrRewritesPayload(t *testing.T) {
	r := setup(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	_, _ = r.Save(ctx, rec("", "g1", t0, "global"))
	_, _ = r.Save(ctx, rec("a", "a1", t0, "scoped"))

	// The scope "a" was replaced by another replica with a different version.
	_, _ = r.Save(ctx, rec("a", "a2", t0.Add(time.Minute), "scoped-new"))

	later := t0.Add(2 * time.Hour)
	if err := r.Touch(ctx, []appsnapshot.LKGVersion{{Scope: "", Version: "g1"}, {Scope: "a", Version: "a1"}}, later); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	rows := byScope(t, r)
	if !rows[""].CompiledAt.Equal(later) || string(rows[""].Payload) != "global" {
		t.Fatalf("a matching row must advance with its payload intact: %+v", rows[""])
	}
	if !rows["a"].CompiledAt.Equal(t0.Add(time.Minute)) || rows["a"].Version != "a2" {
		t.Fatalf("a row holding another version must not be touched: %+v", rows["a"])
	}

	if err := r.Touch(ctx, []appsnapshot.LKGVersion{{Scope: "", Version: "g1"}}, t0); err != nil {
		t.Fatalf("Touch backwards: %v", err)
	}
	if !byScope(t, r)[""].CompiledAt.Equal(later) {
		t.Fatal("a touch must never move compiled_at backwards")
	}
	if err := r.Touch(ctx, nil, later); err != nil {
		t.Fatalf("Touch(nil): %v", err)
	}
}
