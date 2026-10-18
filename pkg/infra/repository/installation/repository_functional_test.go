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
	"errors"
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

// openTestSchema creates the store_installations table in a throwaway schema
// and one gateway row to hang installations off.
func openTestSchema(t *testing.T) (context.Context, *pgxpool.Pool, ids.GatewayID) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	schema := "installation_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open admin pool: %v", err)
	}
	t.Cleanup(admin.Close)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE") })

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
	t.Cleanup(pool.Close)

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
			reason TEXT NOT NULL DEFAULT '',
			requester_groups TEXT[] NOT NULL DEFAULT '{}',
			decision TEXT NOT NULL DEFAULT '',
			decided_by TEXT NOT NULL DEFAULT '',
			decided_at TIMESTAMPTZ NULL,
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
	return ctx, pool, gatewayID
}

func TestRepositoryConcurrentUpsertIsIdempotent(t *testing.T) {
	ctx, pool, gatewayID := openTestSchema(t)
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

func pendingRow(t *testing.T, gatewayID ids.GatewayID, sub, code string, registryID ids.RegistryID) *domain.Installation {
	t.Helper()
	in, err := domain.New(gatewayID, sub, code, sub, nil)
	if err != nil {
		t.Fatalf("new installation: %v", err)
	}
	in.Status = domain.StatusPendingApproval
	in.RegistryID = registryID
	return in
}

func TestRepositoryRebindMovesTheRowInPlace(t *testing.T) {
	ctx, pool, gatewayID := openTestSchema(t)
	repo := NewRepository(&database.Connection{Pool: pool})
	deleted, current := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	request := pendingRow(t, gatewayID, "alice", "com.notion/mcp", deleted)
	if err := repo.Upsert(ctx, request); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := repo.Rebind(ctx, gatewayID, "alice", request.ID, current); err != nil {
		t.Fatalf("Rebind: %v", err)
	}
	found, err := repo.FindByID(ctx, gatewayID, "alice", request.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if found.RegistryID != current {
		t.Fatalf("registry_id = %s, want %s", found.RegistryID, current)
	}

	found.Decide(domain.DecisionApproved, "admin", time.Now().UTC())
	if err := repo.Upsert(ctx, found); err != nil {
		t.Fatalf("Upsert after rebind: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM store_installations`).Scan(&count); err != nil {
		t.Fatalf("count installations: %v", err)
	}
	if count != 1 {
		t.Fatalf("installation rows = %d, want 1: the approve must update the rebound row", count)
	}
}

func TestRepositoryRebindOntoAHeldInstanceIsInstanceExists(t *testing.T) {
	ctx, pool, gatewayID := openTestSchema(t)
	repo := NewRepository(&database.Connection{Pool: pool})
	deleted, current := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	orphan := pendingRow(t, gatewayID, "alice", "com.notion/mcp", deleted)
	fresh := pendingRow(t, gatewayID, "alice", "com.notion/mcp", current)
	for _, in := range []*domain.Installation{orphan, fresh} {
		if err := repo.Upsert(ctx, in); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	if err := repo.Rebind(ctx, gatewayID, "alice", orphan.ID, current); !errors.Is(err, domain.ErrInstanceExists) {
		t.Fatalf("Rebind onto a held instance = %v, want ErrInstanceExists", err)
	}
	if err := repo.Rebind(ctx, gatewayID, "bob", orphan.ID, current); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Rebind of another principal's row = %v, want ErrNotFound", err)
	}
}

func TestRepositoryDenyPendingDeniesOnlyThatCodesPendingRows(t *testing.T) {
	ctx, pool, gatewayID := openTestSchema(t)
	repo := NewRepository(&database.Connection{Pool: pool})
	deleted := ids.New[ids.RegistryKind]()
	code := "custom:" + deleted.String()
	alice := pendingRow(t, gatewayID, "alice", code, deleted)
	bob := pendingRow(t, gatewayID, "bob", code, deleted)
	installed := pendingRow(t, gatewayID, "carol", code, deleted)
	installed.Status = domain.StatusInstalled
	other := pendingRow(t, gatewayID, "alice", "com.notion/mcp", ids.RegistryID{})
	for _, in := range []*domain.Installation{alice, bob, installed, other} {
		if err := repo.Upsert(ctx, in); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	at := time.Now().UTC().Truncate(time.Microsecond)
	denied, err := repo.DenyPending(ctx, gatewayID, code, "system: server deleted", at)
	if err != nil {
		t.Fatalf("DenyPending: %v", err)
	}
	if denied != 2 {
		t.Fatalf("denied = %d, want 2", denied)
	}
	pending, err := repo.ListPendingByGateway(ctx, gatewayID)
	if err != nil {
		t.Fatalf("ListPendingByGateway: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != other.ID {
		t.Fatalf("pending after deny = %+v, want only the other code's request", pending)
	}
	history, err := repo.ListDecidedByGateway(ctx, gatewayID, 10)
	if err != nil {
		t.Fatalf("ListDecidedByGateway: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history = %d rows, want the 2 denied requests", len(history))
	}
	for _, row := range history {
		if row.Decision != domain.DecisionDenied || row.DecidedBy != "system: server deleted" || !row.DecidedAt.Equal(at) {
			t.Fatalf("history row = %+v, want denied by the system at %s", row, at)
		}
	}
	found, err := repo.FindByID(ctx, gatewayID, "carol", installed.ID)
	if err != nil || found.Status != domain.StatusInstalled {
		t.Fatalf("an installed row is not a request and stays installed, got %+v / %v", found, err)
	}
}
