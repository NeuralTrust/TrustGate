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
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const migrationConsumerOne = "11111111-1111-1111-1111-111111111111"
const migrationConsumerTwo = "22222222-2222-2222-2222-222222222222"
const migrationRegistry = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
const migrationGateway = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

func TestCanonicalSmartRoutingMigrationUpIdempotentDown(t *testing.T) {
	ctx, tx := smartRoutingMigrationFixture(t)
	original := migrationStoredLB(t, ctx, tx, migrationConsumerOne)
	if err := upCanonicalizeSmartRouting(ctx, tx); err != nil {
		t.Fatal(err)
	}
	canonical := migrationStoredLB(t, ctx, tx, migrationConsumerOne)
	if equalRoutingJSON(original, canonical) {
		t.Fatal("legacy configuration was not migrated")
	}
	var backedUp []byte
	var count int
	if err := tx.QueryRow(ctx, `SELECT lb_config_before FROM sr1_routing_migration_backup WHERE consumer_id = $1::uuid`, migrationConsumerOne).Scan(&backedUp); err != nil {
		t.Fatal(err)
	}
	if !equalRoutingJSON(original, backedUp) {
		t.Fatal("backup does not preserve original JSON")
	}
	if err := upCanonicalizeSmartRouting(ctx, tx); err != nil {
		t.Fatalf("idempotent up: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sr1_routing_migration_backup`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("backup rows=%d want2", count)
	}
	if err := downCanonicalizeSmartRouting(ctx, tx); err != nil {
		t.Fatalf("down: %v", err)
	}
	if !equalRoutingJSON(original, migrationStoredLB(t, ctx, tx, migrationConsumerOne)) {
		t.Fatal("down did not restore exact configuration")
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('sr1_routing_migration_backup') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("down retained backup table")
	}
	if err := downCanonicalizeSmartRouting(ctx, tx); err != nil {
		t.Fatalf("idempotent down: %v", err)
	}
	if err := upCanonicalizeSmartRouting(ctx, tx); err != nil {
		t.Fatalf("reapply: %v", err)
	}
}

func TestCanonicalSmartRoutingMigrationPreflightWritesNothing(t *testing.T) {
	ctx, tx := smartRoutingMigrationFixture(t)
	if _, err := tx.Exec(ctx, `
		UPDATE consumers SET lb_config = jsonb_set(
		    jsonb_set(lb_config, '{enabled}', 'false'),
		    '{smart_routing,tiers}', jsonb_build_array(lb_config->'smart_routing'->'tiers'->0))
		WHERE id = $1::uuid`, migrationConsumerTwo); err != nil {
		t.Fatal(err)
	}
	one := migrationStoredLB(t, ctx, tx, migrationConsumerOne)
	two := migrationStoredLB(t, ctx, tx, migrationConsumerTwo)
	err := upCanonicalizeSmartRouting(ctx, tx)
	if err == nil || !strings.Contains(err.Error(), migrationConsumerTwo) || !strings.Contains(err.Error(), "no configurations written") {
		t.Fatalf("unresolved preflight=%v", err)
	}
	if !equalRoutingJSON(one, migrationStoredLB(t, ctx, tx, migrationConsumerOne)) || !equalRoutingJSON(two, migrationStoredLB(t, ctx, tx, migrationConsumerTwo)) {
		t.Fatal("preflight rewrote some consumers before failure")
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('sr1_routing_migration_backup') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("preflight created a backup table before all candidates passed")
	}
}

func TestCanonicalSmartRoutingMigrationDownPreservesOwnerEdits(t *testing.T) {
	ctx, tx := smartRoutingMigrationFixture(t)
	if err := upCanonicalizeSmartRouting(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE consumers SET updated_at = updated_at + INTERVAL '1 second' WHERE id = $1::uuid`, migrationConsumerTwo); err != nil {
		t.Fatal(err)
	}
	canonical := migrationStoredLB(t, ctx, tx, migrationConsumerOne)
	if err := downCanonicalizeSmartRouting(ctx, tx); err == nil {
		t.Fatal("down overwrote a later owner edit")
	}
	if !equalRoutingJSON(canonical, migrationStoredLB(t, ctx, tx, migrationConsumerOne)) {
		t.Fatal("down partially restored before conflict detection")
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sr1_routing_migration_backup`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatal("conflicted rollback discarded evidence")
	}
}

func smartRoutingMigrationFixture(t *testing.T) (context.Context, pgx.Tx) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatalf("connect: %v", err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		_ = conn.Close(context.Background())
		cancel()
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_ = tx.Rollback(cleanupCtx)
		_ = conn.Close(cleanupCtx)
		cancel()
	})
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE consumers (
			id UUID PRIMARY KEY, gateway_id UUID NOT NULL,
			lb_config JSONB, model_policies JSONB, fallback JSONB,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT '2026-10-01T00:00:00Z'
		) ON COMMIT DROP;
		CREATE TEMP TABLE registries (id UUID PRIMARY KEY, gateway_id UUID NOT NULL) ON COMMIT DROP;
		CREATE TEMP TABLE consumer_registry (consumer_id UUID, registry_id UUID) ON COMMIT DROP;
		SET LOCAL search_path TO pg_temp`); err != nil {
		t.Fatalf("fixture tables: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO registries VALUES ($1::uuid, $2::uuid)`, migrationRegistry, migrationGateway); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"enabled": true, "algorithm": "smart-routing", "pool_alias": "preserved",
		"members":       []map[string]any{{"registry_id": migrationRegistry, "model": "high"}, {"registry_id": migrationRegistry, "model": "low"}},
		"smart_routing": map[string]any{"tiers": []map[string]any{{"registry_id": migrationRegistry, "model": "high", "min_score": .8}, {"registry_id": migrationRegistry, "model": "low", "min_score": .1}}}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	policies := `{"` + migrationRegistry + `":{"allowed":["low","high"]}}`
	for _, id := range []string{migrationConsumerOne, migrationConsumerTwo} {
		if _, err := tx.Exec(ctx, `INSERT INTO consumers (id, gateway_id, lb_config, model_policies) VALUES ($1::uuid, $2::uuid, $3::jsonb, $4::jsonb)`, id, migrationGateway, raw, policies); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO consumer_registry VALUES ($1::uuid, $2::uuid)`, id, migrationRegistry); err != nil {
			t.Fatal(err)
		}
	}
	return ctx, tx
}

func migrationStoredLB(t *testing.T, ctx context.Context, tx pgx.Tx, id string) []byte {
	t.Helper()
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT lb_config FROM consumers WHERE id = $1::uuid`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}
