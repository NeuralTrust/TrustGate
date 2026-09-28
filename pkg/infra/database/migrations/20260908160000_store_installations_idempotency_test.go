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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestStoreInstallationsIdempotencyMigration(t *testing.T) {
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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

	const setup = `
		CREATE TEMP TABLE store_installations (
			id UUID PRIMARY KEY,
			gateway_id UUID NOT NULL,
			principal_sub TEXT NOT NULL,
			catalog_code TEXT NOT NULL,
			status TEXT NOT NULL,
			config JSONB,
			registry_id UUID,
			created_at TIMESTAMPTZ NOT NULL
		) ON COMMIT DROP;
		SET LOCAL search_path TO pg_temp;`
	if _, err := tx.Exec(ctx, setup); err != nil {
		t.Fatalf("setup: %v", err)
	}
	gatewayID := uuid.New()
	firstID := uuid.New()
	secondID := uuid.New()
	if _, err := tx.Exec(ctx, `
		INSERT INTO store_installations
			(id, gateway_id, principal_sub, catalog_code, status, config, registry_id, created_at)
		VALUES
			($1, $3, 'alice', 'github', 'revoked', '{"host":"acme"}', NULL, now() - interval '1 minute'),
			($2, $3, 'alice', 'github', 'installed', '{"host":"acme"}', NULL, now())`,
		firstID, secondID, gatewayID,
	); err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}
	if _, err := tx.Exec(ctx, storeInstallationsIdempotencyUp); err != nil {
		t.Fatalf("up migration: %v", err)
	}

	var keptID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM store_installations`).Scan(&keptID); err != nil {
		t.Fatalf("read retained row: %v", err)
	}
	if keptID != secondID {
		t.Fatalf("retained id = %s, want installed row %s", keptID, secondID)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO store_installations
			(id, gateway_id, principal_sub, catalog_code, status, config, registry_id, created_at)
		VALUES ($1, $2, 'alice', 'github', 'installed', '{"host":"acme"}', NULL, now())`,
		uuid.New(), gatewayID,
	); err == nil {
		t.Fatal("duplicate logical installation was accepted")
	}
}
