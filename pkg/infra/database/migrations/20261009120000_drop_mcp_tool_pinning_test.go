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
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The schema the withdrawn pinning migration left behind, with a pinned
// registry and one of its tools in it.
const dropMCPToolPinningSetup = `
	CREATE TEMP TABLE registries (
		id          UUID PRIMARY KEY,
		name        TEXT NOT NULL,
		tool_policy TEXT NOT NULL DEFAULT 'auto',
		CONSTRAINT registries_tool_policy_check CHECK (tool_policy IN ('auto', 'pinned'))
	) ON COMMIT DROP;
	CREATE TEMP TABLE registry_tools (
		registry_id UUID NOT NULL REFERENCES registries (id) ON DELETE CASCADE,
		tool_name   TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		PRIMARY KEY (registry_id, tool_name, fingerprint)
	) ON COMMIT DROP;
	SET LOCAL search_path TO pg_temp;

	INSERT INTO registries (id, name, tool_policy) VALUES
		('11111111-1111-1111-1111-111111111111', 'Linear', 'pinned');
	INSERT INTO registry_tools (registry_id, tool_name, fingerprint) VALUES
		('11111111-1111-1111-1111-111111111111', 'create_issue', 'abc');`

func TestDropMCPToolPinningMigration(t *testing.T) {
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, dropMCPToolPinningSetup); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := upDropMCPToolPinning(ctx, tx); err != nil {
		t.Fatalf("up: %v", err)
	}
	assertPinningSchemaGone(t, ctx, tx)

	var name string
	if err := tx.QueryRow(ctx,
		`SELECT name FROM registries WHERE id = '11111111-1111-1111-1111-111111111111'`,
	).Scan(&name); err != nil || name != "Linear" {
		t.Fatalf("the registry did not survive the drop: name %q, err %v", name, err)
	}

	// A database that never applied the pinning migration, or this one twice.
	if err := upDropMCPToolPinning(ctx, tx); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	assertPinningSchemaGone(t, ctx, tx)
}

func assertPinningSchemaGone(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	var table *string
	if err := tx.QueryRow(ctx, `SELECT to_regclass('registry_tools')::text`).Scan(&table); err != nil {
		t.Fatalf("look up registry_tools: %v", err)
	}
	if table != nil {
		t.Fatalf("registry_tools still exists")
	}
	var columns int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_attribute
		 WHERE attrelid = 'registries'::regclass AND attname = 'tool_policy' AND NOT attisdropped`,
	).Scan(&columns); err != nil {
		t.Fatalf("look up registries.tool_policy: %v", err)
	}
	if columns != 0 {
		t.Fatalf("registries.tool_policy still exists")
	}
}
