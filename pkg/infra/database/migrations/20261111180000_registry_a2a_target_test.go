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

func TestRegistryA2ATargetUpAndDown(t *testing.T) {
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE registries (
			id SERIAL PRIMARY KEY,
			type TEXT NOT NULL DEFAULT 'LLM' CONSTRAINT registries_type_check CHECK (type IN ('LLM', 'MCP'))
		) ON COMMIT DROP;
		SET LOCAL search_path TO pg_temp`); err != nil {
		t.Fatalf("setup: %v", err)
	}
	for range 2 {
		if err := upRegistryA2ATarget(ctx, tx); err != nil {
			t.Fatalf("up: %v", err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO registries (type, a2a_target) VALUES ('A2A', '{"card_url":"https://a.example.com"}')`); err != nil {
		t.Fatalf("insert A2A: %v", err)
	}

	if _, err := tx.Exec(ctx, `SAVEPOINT before_down`); err != nil {
		t.Fatalf("savepoint: %v", err)
	}
	if err := downRegistryA2ATarget(ctx, tx); err == nil {
		t.Fatal("down succeeded with A2A registries present")
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT before_down; DELETE FROM registries WHERE type = 'A2A'`); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if err := downRegistryA2ATarget(ctx, tx); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err := tx.Exec(ctx, `SAVEPOINT after_down`); err != nil {
		t.Fatalf("savepoint: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO registries (type) VALUES ('A2A')`); err == nil {
		t.Fatal("type check accepts A2A after down")
	}
}
