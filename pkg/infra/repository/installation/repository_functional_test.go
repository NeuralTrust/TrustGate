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

package installation

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRepositoryConcurrentUpsertIsIdempotent(t *testing.T) {
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	schema := "installation_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open admin pool: %v", err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE") }()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	cfg.MaxConns = 8
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET search_path TO "+quotedSchema)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open test pool: %v", err)
	}
	defer pool.Close()

	const setup = `
		CREATE TABLE gateways (id UUID PRIMARY KEY);
		CREATE TABLE store_installations (
			id UUID PRIMARY KEY,
			gateway_id UUID NOT NULL REFERENCES gateways(id),
			principal_sub TEXT NOT NULL,
			catalog_code TEXT NOT NULL,
			status TEXT NOT NULL,
			installed_by TEXT NOT NULL DEFAULT '',
			config JSONB,
			registry_id UUID,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		);
		CREATE UNIQUE INDEX uq_store_installations_logical_instance
			ON store_installations (
				gateway_id,
				principal_sub,
				catalog_code,
				COALESCE(registry_id, '00000000-0000-0000-0000-000000000000'::uuid),
			COALESCE(config, '{}'::jsonb)
			);`
	if _, err := pool.Exec(ctx, setup); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	gatewayID, err := ids.NewV7[ids.GatewayKind]()
	if err != nil {
		t.Fatalf("gateway id: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO gateways (id) VALUES ($1)`, gatewayID); err != nil {
		t.Fatalf("insert gateway: %v", err)
	}

	repo := NewRepository(&database.Connection{Pool: pool})
	const workers = 16
	installations := make([]*domain.Installation, workers)
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := range workers {
		in, err := domain.New(gatewayID, "alice", "github", "alice", map[string]string{"host": "acme"})
		if err != nil {
			t.Fatalf("new installation: %v", err)
		}
		installations[i] = in
		wg.Add(1)
		go func(in *domain.Installation) {
			defer wg.Done()
			if err := repo.Upsert(ctx, in); err != nil {
				errs <- err
			}
		}(in)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent upsert: %v", err)
	}
	if t.Failed() {
		return
	}

	canonicalID := installations[0].ID
	for i, in := range installations {
		if in.ID != canonicalID {
			t.Fatalf("installation %d id = %s, want canonical %s", i, in.ID, canonicalID)
		}
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM store_installations`).Scan(&count); err != nil {
		t.Fatalf("count installations: %v", err)
	}
	if count != 1 {
		t.Fatalf("installation rows = %d, want 1", count)
	}
	found, err := repo.FindByID(ctx, gatewayID, "alice", canonicalID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if !found.SameConfig(map[string]string{"host": "acme"}) {
		t.Fatalf("stored config = %v", found.Config)
	}
}
