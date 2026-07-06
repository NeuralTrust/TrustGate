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

package postgres

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/jackc/pgx/v5/pgxpool"
)

// advisoryLockKey serializes first-time DDL across replicas that enable the
// exporter concurrently. The value is arbitrary but must stay stable (ENG-1020).
const advisoryLockKey int64 = 942_020

func runMigrations(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres: acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		return fmt.Errorf("postgres: acquire advisory lock: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", advisoryLockKey); unlockErr != nil {
			logger.Warn("postgres: release advisory lock failed", slog.String("error", unlockErr.Error()))
		}
	}()

	if _, err := conn.Exec(ctx, ensureMigrationsTableSQL); err != nil {
		return fmt.Errorf("postgres: ensure schema_migrations: %w", err)
	}
	applied, err := appliedMigrations(ctx, conn)
	if err != nil {
		return err
	}
	for _, m := range metrics.Migrations() {
		if applied[m.ID] {
			continue
		}
		if err := applyMigration(ctx, conn, m); err != nil {
			return fmt.Errorf("postgres: apply migration %q: %w", m.ID, err)
		}
	}
	return nil
}

const ensureMigrationsTableSQL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    id         TEXT        PRIMARY KEY,
    name       TEXT        NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

func appliedMigrations(ctx context.Context, conn *pgxpool.Conn) (map[string]bool, error) {
	rows, err := conn.Query(ctx, "SELECT id FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("postgres: load applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("postgres: scan migration id: %w", err)
		}
		applied[id] = true
	}
	return applied, rows.Err()
}

func applyMigration(ctx context.Context, conn *pgxpool.Conn, m metrics.Migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, m.UpSQL); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (id, name) VALUES ($1, $2)", m.ID, m.Name); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
