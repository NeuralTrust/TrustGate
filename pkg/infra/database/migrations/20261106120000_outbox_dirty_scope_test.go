//go:build functional

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

package migrations

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestOutboxDirtyScopeMigrationFailsFastBehindAnOpenWrite(t *testing.T) {
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	schema := fmt.Sprintf("outbox_lock_%d", time.Now().UnixNano())
	writer := connectInSchema(t, ctx, dsn, schema, true)
	migrator := connectInSchema(t, ctx, dsn, schema, false)
	t.Cleanup(func() {
		_, _ = writer.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})

	if _, err := writer.Exec(ctx, `CREATE TABLE config_snapshot_outbox (
		seq BIGSERIAL PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatalf("create outbox: %v", err)
	}

	write, err := writer.Begin(ctx)
	if err != nil {
		t.Fatalf("begin write: %v", err)
	}
	if _, err := write.Exec(ctx, `INSERT INTO config_snapshot_outbox DEFAULT VALUES`); err != nil {
		t.Fatalf("insert marker: %v", err)
	}

	started := time.Now()
	err = runInTx(ctx, migrator, upOutboxDirtyScope)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("up behind an open write: want lock_not_available (55P03), got %v", err)
	}
	if waited := time.Since(started); waited > 10*time.Second {
		t.Fatalf("up waited %s behind the open write; the lock timeout should end it in about 5s", waited)
	}

	if err := write.Commit(ctx); err != nil {
		t.Fatalf("commit write: %v", err)
	}
	if err := runInTx(ctx, migrator, upOutboxDirtyScope); err != nil {
		t.Fatalf("up once the write committed: %v", err)
	}
	if _, err := writer.Exec(ctx, `INSERT INTO config_snapshot_outbox (kind, gateway_id) VALUES ('all', NULL)`); err != nil {
		t.Fatalf("insert with the new columns: %v", err)
	}
	if err := runInTx(ctx, migrator, downOutboxDirtyScope); err != nil {
		t.Fatalf("down: %v", err)
	}
}

func connectInSchema(t *testing.T, ctx context.Context, dsn, schema string, create bool) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if create {
		if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}
	if _, err := conn.Exec(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatalf("set search_path: %v", err)
	}
	return conn
}

func runInTx(ctx context.Context, conn *pgx.Conn, fn func(context.Context, pgx.Tx) error) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(ctx, tx); err != nil {
		_ = tx.Rollback(context.Background())
		return err
	}
	return tx.Commit(ctx)
}
