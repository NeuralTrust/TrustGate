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

	"github.com/NeuralTrust/TrustGate/pkg/config"
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

	count, err := repo.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
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

	count, err := repo.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if count != 0 {
		t.Fatalf("rolled-back AppendTx must leave no marker, got %d", count)
	}
}

func TestIntegration_MaxSeqAndDeleteUpTo(t *testing.T) {
	conn, repo := setupRepository(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := database.WithTx(ctx, conn, func(tx pgx.Tx) error { return repo.AppendTx(ctx, tx) }); err != nil {
			t.Fatalf("AppendTx %d: %v", i, err)
		}
	}

	maxSeq, err := repo.MaxSeq(ctx)
	if err != nil {
		t.Fatalf("MaxSeq: %v", err)
	}
	if maxSeq < 3 {
		t.Fatalf("MaxSeq must be at least 3 after three appends, got %d", maxSeq)
	}

	// A marker inserted after the frontier snapshot must survive DeleteUpTo(maxSeq).
	if err := database.WithTx(ctx, conn, func(tx pgx.Tx) error { return repo.AppendTx(ctx, tx) }); err != nil {
		t.Fatalf("AppendTx (post-frontier): %v", err)
	}

	deleted, err := repo.DeleteUpTo(ctx, maxSeq)
	if err != nil {
		t.Fatalf("DeleteUpTo: %v", err)
	}
	if deleted != 3 {
		t.Fatalf("DeleteUpTo(%d) must delete the three markers at or below the frontier, got %d", maxSeq, deleted)
	}
	count, err := repo.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if count != 1 {
		t.Fatalf("the post-frontier marker must survive DeleteUpTo, got %d remaining", count)
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
	count, err := repo.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
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
