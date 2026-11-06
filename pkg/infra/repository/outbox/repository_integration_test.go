//go:build integration

// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package outbox

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	// Register the outbox migration (and the rest of the schema) with the database registry.
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	"github.com/jackc/pgx/v5"
)

// setupRepository builds a connection to a local Postgres and applies pending
// migrations. It skips the test when no database is reachable so the integration
// suite can run in environments without Postgres. Connection settings come from
// the TEST_DB_* env vars, defaulting to the local functional database.
func setupRepository(t *testing.T) (*database.Connection, *Repository) {
	t.Helper()
	ctx := context.Background()

	port := 5432
	if raw := os.Getenv("TEST_DB_PORT"); raw != "" {
		if p, err := strconv.Atoi(raw); err == nil {
			port = p
		}
	}
	cfg := &config.DatabaseConfig{
		Host:              envOr("TEST_DB_HOST", "localhost"),
		Port:              port,
		User:              envOr("TEST_DB_USER", "postgres"),
		Password:          envOr("TEST_DB_PASSWORD", "postgres"),
		Name:              envOr("TEST_DB_NAME", "trustgate_functional"),
		SSLMode:           envOr("TEST_DB_SSLMODE", "disable"),
		MinConns:          1,
		MaxConns:          5,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   30 * time.Minute,
		HealthCheckPeriod: time.Minute,
		ConnectTimeout:    5 * time.Second,
	}

	conn, err := database.NewConnection(ctx, cfg)
	if err != nil {
		t.Skipf("no reachable Postgres for the outbox integration test: %v", err)
	}
	t.Cleanup(conn.Close)

	// The migration is idempotent: applying twice must not fail.
	if err := database.NewMigrationsManager(conn.Pool).ApplyPending(ctx); err != nil {
		t.Fatalf("ApplyPending: %v", err)
	}
	if err := database.NewMigrationsManager(conn.Pool).ApplyPending(ctx); err != nil {
		t.Fatalf("ApplyPending (re-run): %v", err)
	}

	// Start each test from an empty outbox so counts are deterministic.
	if _, err := conn.Pool.Exec(ctx, `DELETE FROM config_snapshot_outbox`); err != nil {
		t.Fatalf("truncate outbox: %v", err)
	}
	return conn, NewRepository(conn)
}

func countMarkers(t *testing.T, conn *database.Connection) int64 {
	t.Helper()
	var count int64
	if err := conn.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM config_snapshot_outbox`).Scan(&count); err != nil {
		t.Fatalf("count markers: %v", err)
	}
	return count
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func TestIntegration_AppendTxCommitsMarker(t *testing.T) {
	conn, repo := setupRepository(t)
	ctx := context.Background()

	if err := database.WithTx(ctx, conn, func(tx pgx.Tx) error {
		return repo.AppendTx(ctx, tx)
	}); err != nil {
		t.Fatalf("AppendTx (commit): %v", err)
	}

	count := countMarkers(t, conn)
	if count != 1 {
		t.Fatalf("committed AppendTx must leave one marker, got %d", count)
	}
}

func TestIntegration_AppendTxRollbackDropsMarker(t *testing.T) {
	conn, repo := setupRepository(t)
	ctx := context.Background()

	sentinel := errorString("forced rollback")
	err := database.WithTx(ctx, conn, func(tx pgx.Tx) error {
		if err := repo.AppendTx(ctx, tx); err != nil {
			return err
		}
		return sentinel
	})
	if err == nil {
		t.Fatal("WithTx must surface the forced rollback error")
	}

	count := countMarkers(t, conn)
	if count != 0 {
		t.Fatalf("rolled-back AppendTx must leave no marker, got %d", count)
	}
}

func TestIntegration_PruneOlderThanEnforcesRowBound(t *testing.T) {
	conn, repo := setupRepository(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := database.WithTx(ctx, conn, func(tx pgx.Tx) error { return repo.AppendTx(ctx, tx) }); err != nil {
			t.Fatalf("AppendTx %d: %v", i, err)
		}
	}

	// keepMax=2 with a future cutoff would prune everything by age, so use a past
	// cutoff to isolate the row bound: only the newest two markers survive.
	deleted, err := repo.PruneOlderThan(ctx, time.Now().Add(-time.Hour), 2)
	if err != nil {
		t.Fatalf("PruneOlderThan: %v", err)
	}
	if deleted != 3 {
		t.Fatalf("PruneOlderThan must delete the three oldest markers beyond the keepMax bound, got %d", deleted)
	}
	count := countMarkers(t, conn)
	if count != 2 {
		t.Fatalf("the newest keepMax markers must survive the row bound, got %d", count)
	}

	// A cutoff in the future prunes the remainder by age.
	deleted, err = repo.PruneOlderThan(ctx, time.Now().Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("PruneOlderThan (age): %v", err)
	}
	if deleted != 2 {
		t.Fatalf("PruneOlderThan with a future cutoff must delete the remaining markers, got %d", deleted)
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

func TestIntegration_ReadSinceDecodesWhatEachMarkerDirtied(t *testing.T) {
	conn, repo := setupRepository(t)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()

	appends := []func(pgx.Tx) error{
		func(tx pgx.Tx) error { return repo.AppendGatewayTx(ctx, tx, gw) },
		func(tx pgx.Tx) error { return repo.AppendCatalogTx(ctx, tx) },
		func(tx pgx.Tx) error { return repo.AppendTx(ctx, tx) },
		func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO config_snapshot_outbox DEFAULT VALUES`)
			return err
		},
	}
	for i, appendFn := range appends {
		if err := database.WithTx(ctx, conn, appendFn); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	markers, bounds, err := repo.ReadSince(ctx, 0)
	if err != nil {
		t.Fatalf("ReadSince: %v", err)
	}
	wantKinds := []configsyncport.MarkerKind{configsyncport.MarkerGateway, configsyncport.MarkerCatalog, configsyncport.MarkerAll, configsyncport.MarkerAll}
	if len(markers) != len(wantKinds) {
		t.Fatalf("ReadSince returned %d markers, want %d", len(markers), len(wantKinds))
	}
	for i, want := range wantKinds {
		if markers[i].Kind != want {
			t.Fatalf("marker %d kind = %q, want %q", i, markers[i].Kind, want)
		}
	}
	if markers[0].GatewayID != gw {
		t.Fatalf("gateway marker names %s, want %s", markers[0].GatewayID, gw)
	}
	if bounds.Min != markers[0].Seq || bounds.Max != markers[len(markers)-1].Seq {
		t.Fatalf("bounds = %+v, want the oldest seq %d and the newest %d", bounds, markers[0].Seq, markers[len(markers)-1].Seq)
	}

	after, _, err := repo.ReadSince(ctx, markers[1].Seq)
	if err != nil {
		t.Fatalf("ReadSince after: %v", err)
	}
	if len(after) != 2 || after[0].Seq != markers[2].Seq {
		t.Fatalf("ReadSince must return only markers above afterSeq, got %+v", after)
	}
}

func TestIntegration_ReadSinceSeesALowerSeqThatCommitsLater(t *testing.T) {
	conn, repo := setupRepository(t)
	ctx := context.Background()

	txA, err := conn.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin txA: %v", err)
	}
	defer func() { _ = txA.Rollback(ctx) }()
	if err := repo.AppendGatewayTx(ctx, txA, ids.New[ids.GatewayKind]()); err != nil {
		t.Fatalf("append A: %v", err)
	}
	if err := database.WithTx(ctx, conn, func(tx pgx.Tx) error { return repo.AppendCatalogTx(ctx, tx) }); err != nil {
		t.Fatalf("append B: %v", err)
	}

	visible, _, err := repo.ReadSince(ctx, 0)
	if err != nil {
		t.Fatalf("ReadSince: %v", err)
	}
	if len(visible) != 1 || visible[0].Kind != configsyncport.MarkerCatalog {
		t.Fatalf("only B must be visible while A is in flight, got %+v", visible)
	}

	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("commit txA: %v", err)
	}
	later, _, err := repo.ReadSince(ctx, 0)
	if err != nil {
		t.Fatalf("ReadSince after commit: %v", err)
	}
	if len(later) != 2 || later[0].Kind != configsyncport.MarkerGateway || later[0].Seq >= visible[0].Seq {
		t.Fatalf("A's lower seq must become visible after it commits, got %+v", later)
	}
}

func TestIntegration_ReadSinceReportsPrunedRows(t *testing.T) {
	conn, repo := setupRepository(t)
	ctx := context.Background()

	if _, bounds, err := repo.ReadSince(ctx, 0); err != nil || bounds != (configsyncport.OutboxBounds{}) {
		t.Fatalf("empty outbox: bounds = %+v, err = %v; want zero", bounds, err)
	}
	for i := 0; i < 3; i++ {
		if err := database.WithTx(ctx, conn, func(tx pgx.Tx) error { return repo.AppendTx(ctx, tx) }); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	markers, _, err := repo.ReadSince(ctx, 0)
	if err != nil {
		t.Fatalf("ReadSince: %v", err)
	}
	if _, err := repo.PruneOlderThan(ctx, time.Now().Add(-time.Hour), 1); err != nil {
		t.Fatalf("PruneOlderThan: %v", err)
	}
	rest, bounds, err := repo.ReadSince(ctx, markers[2].Seq)
	if err != nil {
		t.Fatalf("ReadSince after prune: %v", err)
	}
	if len(rest) != 0 || bounds.Min != markers[2].Seq || bounds.Max != markers[2].Seq {
		t.Fatalf("after the prune bounds = %+v (want %d..%d) and no newer markers, got %+v", bounds, markers[2].Seq, markers[2].Seq, rest)
	}
}

func TestIntegration_ReadSeqsReturnsOnlyVisibleRequestedMarkers(t *testing.T) {
	conn, repo := setupRepository(t)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()

	txLate, err := conn.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin late tx: %v", err)
	}
	defer func() { _ = txLate.Rollback(ctx) }()
	if err := repo.AppendGatewayTx(ctx, txLate, gw); err != nil {
		t.Fatalf("append late: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := database.WithTx(ctx, conn, func(tx pgx.Tx) error { return repo.AppendCatalogTx(ctx, tx) }); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	visible, _, err := repo.ReadSince(ctx, 0)
	if err != nil {
		t.Fatalf("ReadSince: %v", err)
	}
	if len(visible) != 2 {
		t.Fatalf("only the two committed markers must be visible, got %+v", visible)
	}
	lateSeq := visible[0].Seq - 1

	if got, err := repo.ReadSeqs(ctx, []int64{lateSeq}); err != nil || len(got) != 0 {
		t.Fatalf("an uncommitted seq must not be returned, got %+v err=%v", got, err)
	}
	if err := txLate.Commit(ctx); err != nil {
		t.Fatalf("commit late tx: %v", err)
	}

	got, err := repo.ReadSeqs(ctx, []int64{visible[1].Seq, lateSeq, visible[1].Seq + 1000})
	if err != nil {
		t.Fatalf("ReadSeqs: %v", err)
	}
	if len(got) != 2 || got[0].Seq != lateSeq || got[0].Kind != configsyncport.MarkerGateway || got[0].GatewayID != gw || got[1].Seq != visible[1].Seq {
		t.Fatalf("ReadSeqs must return the requested visible markers oldest first, decoded, got %+v", got)
	}
	if got, err := repo.ReadSeqs(ctx, nil); err != nil || got != nil {
		t.Fatalf("an empty request reads nothing, got %+v err=%v", got, err)
	}
}
