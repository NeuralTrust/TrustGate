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
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const danglingTierSetup = `
	CREATE TEMP TABLE consumers (
		id         UUID PRIMARY KEY,
		lb_config  JSONB,
		fallback   JSONB,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	) ON COMMIT DROP;
	CREATE TEMP TABLE consumer_registry (
		consumer_id UUID NOT NULL,
		registry_id UUID NOT NULL
	) ON COMMIT DROP;
	SET LOCAL search_path TO pg_temp;

	INSERT INTO consumer_registry (consumer_id, registry_id) VALUES
		('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000000a'),
		('22222222-2222-2222-2222-222222222222', 'aaaaaaaa-0000-0000-0000-00000000000a'),
		('33333333-3333-3333-3333-333333333333', 'aaaaaaaa-0000-0000-0000-00000000000a'),
		('44444444-4444-4444-4444-444444444444', 'aaaaaaaa-0000-0000-0000-00000000000a'),
		('66666666-6666-6666-6666-666666666666', 'aaaaaaaa-0000-0000-0000-00000000000a');

	INSERT INTO consumers (id, lb_config, fallback) VALUES
		-- The cheapest tier is the dangling one: the ladder cannot survive it.
		('11111111-1111-1111-1111-111111111111', '{
			"enabled": false,
			"algorithm": "smart-routing",
			"pool_alias": "support",
			"members": [{"registry_id": "aaaaaaaa-0000-0000-0000-00000000000a", "model": "gpt-4o"}],
			"smart_routing": {"tiers": [
				{"min_score": 0, "registry_id": "dddddddd-0000-0000-0000-00000000000d"},
				{"min_score": 0.6, "registry_id": "aaaaaaaa-0000-0000-0000-00000000000a"}
			]}
		}', NULL),
		-- A dangling tier above the floor: drop the tier, keep the ladder.
		('22222222-2222-2222-2222-222222222222', '{
			"enabled": false,
			"algorithm": "smart-routing",
			"members": [{"registry_id": "aaaaaaaa-0000-0000-0000-00000000000a", "model": "gpt-4o"}],
			"smart_routing": {"tiers": [
				{"min_score": 0, "registry_id": "aaaaaaaa-0000-0000-0000-00000000000a"},
				{"min_score": 0.6, "registry_id": "dddddddd-0000-0000-0000-00000000000d"}
			]}
		}', NULL),
		-- Every tier dangling, including a nil registry id.
		('33333333-3333-3333-3333-333333333333', '{
			"enabled": false,
			"algorithm": "smart-routing",
			"members": [{"registry_id": "aaaaaaaa-0000-0000-0000-00000000000a", "model": "gpt-4o"}],
			"smart_routing": {"tiers": [
				{"min_score": 0, "registry_id": "00000000-0000-0000-0000-000000000000"},
				{"min_score": 0.4, "registry_id": "dddddddd-0000-0000-0000-00000000000d"}
			]}
		}', NULL),
		-- Already valid: must not be touched at all.
		('44444444-4444-4444-4444-444444444444', '{
			"enabled": true,
			"algorithm": "smart-routing",
			"members": [{"registry_id": "aaaaaaaa-0000-0000-0000-00000000000a", "model": "gpt-4o"}],
			"smart_routing": {"tiers": [
				{"min_score": 0, "registry_id": "aaaaaaaa-0000-0000-0000-00000000000a"}
			]}
		}', NULL),
		-- No consumer_registry row, but the tier registry is a fallback step,
		-- which Consumer.knownRegistryIDs counts as known.
		('55555555-5555-5555-5555-555555555555', '{
			"enabled": false,
			"algorithm": "smart-routing",
			"members": [{"registry_id": "bbbbbbbb-0000-0000-0000-00000000000b", "model": "gpt-4o"}],
			"smart_routing": {"tiers": [
				{"min_score": 0, "registry_id": "bbbbbbbb-0000-0000-0000-00000000000b"}
			]}
		}', '{"enabled": true, "chain": ["bbbbbbbb-0000-0000-0000-00000000000b"]}'),
		-- smart_routing present but tiers absent: must not raise.
		('66666666-6666-6666-6666-666666666666', '{
			"enabled": false,
			"algorithm": "round-robin",
			"members": [{"registry_id": "aaaaaaaa-0000-0000-0000-00000000000a", "model": "gpt-4o"}],
			"smart_routing": {}
		}', NULL),
		-- No lb_config at all.
		('77777777-7777-7777-7777-777777777777', NULL, NULL);`

type lbConfigState struct {
	hasSmartRouting  bool
	algorithm        string
	tierRegistries   []string
	memberRegistries []string
}

func TestPruneDanglingSmartRoutingTiersMigration(t *testing.T) {
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

	if _, err := tx.Exec(ctx, danglingTierSetup); err != nil {
		t.Fatalf("setup: %v", err)
	}
	untouchedBefore := lbConfigJSON(t, ctx, tx, "44444444-4444-4444-4444-444444444444")

	if err := upPruneDanglingSmartRoutingTiers(ctx, tx); err != nil {
		t.Fatalf("up: %v", err)
	}

	assertLBConfig(t, ctx, tx, "11111111-1111-1111-1111-111111111111", lbConfigState{
		hasSmartRouting:  false,
		algorithm:        "round-robin",
		memberRegistries: []string{"aaaaaaaa-0000-0000-0000-00000000000a"},
	})
	assertPoolAlias(t, ctx, tx, "11111111-1111-1111-1111-111111111111", "support")
	assertLBConfig(t, ctx, tx, "22222222-2222-2222-2222-222222222222", lbConfigState{
		hasSmartRouting:  true,
		algorithm:        "smart-routing",
		tierRegistries:   []string{"aaaaaaaa-0000-0000-0000-00000000000a"},
		memberRegistries: []string{"aaaaaaaa-0000-0000-0000-00000000000a"},
	})
	assertLBConfig(t, ctx, tx, "33333333-3333-3333-3333-333333333333", lbConfigState{
		hasSmartRouting:  false,
		algorithm:        "round-robin",
		memberRegistries: []string{"aaaaaaaa-0000-0000-0000-00000000000a"},
	})
	assertLBConfig(t, ctx, tx, "44444444-4444-4444-4444-444444444444", lbConfigState{
		hasSmartRouting:  true,
		algorithm:        "smart-routing",
		tierRegistries:   []string{"aaaaaaaa-0000-0000-0000-00000000000a"},
		memberRegistries: []string{"aaaaaaaa-0000-0000-0000-00000000000a"},
	})
	if after := lbConfigJSON(t, ctx, tx, "44444444-4444-4444-4444-444444444444"); after != untouchedBefore {
		t.Fatalf("a consumer with no dangling tier was rewritten:\n before %s\n after  %s", untouchedBefore, after)
	}
	assertLBConfig(t, ctx, tx, "55555555-5555-5555-5555-555555555555", lbConfigState{
		hasSmartRouting:  true,
		algorithm:        "smart-routing",
		tierRegistries:   []string{"bbbbbbbb-0000-0000-0000-00000000000b"},
		memberRegistries: []string{"bbbbbbbb-0000-0000-0000-00000000000b"},
	})
	assertLBConfig(t, ctx, tx, "66666666-6666-6666-6666-666666666666", lbConfigState{
		hasSmartRouting:  true,
		algorithm:        "round-robin",
		memberRegistries: []string{"aaaaaaaa-0000-0000-0000-00000000000a"},
	})
	assertLBConfig(t, ctx, tx, "77777777-7777-7777-7777-777777777777", lbConfigState{})

	// Idempotency: the statement selects only consumers that still carry an
	// unknown tier, and the first run leaves none, so replaying it must be a
	// byte-for-byte no-op across every row.
	settled := allLBConfigJSON(t, ctx, tx)
	if err := downPruneDanglingSmartRoutingTiers(ctx, tx); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := upPruneDanglingSmartRoutingTiers(ctx, tx); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	replayed := allLBConfigJSON(t, ctx, tx)
	if len(settled) != len(replayed) {
		t.Fatalf("row count changed: %d then %d", len(settled), len(replayed))
	}
	for id, want := range settled {
		if replayed[id] != want {
			t.Fatalf("%s changed on replay:\n first  %s\n second %s", id, want, replayed[id])
		}
	}
}

func lbConfigJSON(t *testing.T, ctx context.Context, tx pgx.Tx, id string) string {
	t.Helper()
	var out *string
	if err := tx.QueryRow(ctx,
		`SELECT lb_config::text FROM consumers WHERE id = $1`, id,
	).Scan(&out); err != nil {
		t.Fatalf("read lb_config for %s: %v", id, err)
	}
	if out == nil {
		return ""
	}
	return *out
}

func allLBConfigJSON(t *testing.T, ctx context.Context, tx pgx.Tx) map[string]string {
	t.Helper()
	rows, err := tx.Query(ctx, `SELECT id::text, COALESCE(lb_config::text, '') FROM consumers`)
	if err != nil {
		t.Fatalf("read every lb_config: %v", err)
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var id, cfg string
		if err := rows.Scan(&id, &cfg); err != nil {
			t.Fatalf("scan lb_config: %v", err)
		}
		out[id] = cfg
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iter lb_config: %v", err)
	}
	return out
}

func assertPoolAlias(t *testing.T, ctx context.Context, tx pgx.Tx, id, want string) {
	t.Helper()
	var got string
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(lb_config->>'pool_alias', '') FROM consumers WHERE id = $1`, id,
	).Scan(&got); err != nil {
		t.Fatalf("read pool_alias for %s: %v", id, err)
	}
	if got != want {
		t.Fatalf("%s pool_alias = %q, want %q", id, got, want)
	}
}

func assertLBConfig(t *testing.T, ctx context.Context, tx pgx.Tx, id string, want lbConfigState) {
	t.Helper()
	const query = `
		SELECT COALESCE(lb_config ? 'smart_routing', false),
		       COALESCE(lb_config->>'algorithm', ''),
		       COALESCE((SELECT array_agg(t->>'registry_id' ORDER BY ord)
		                   FROM jsonb_array_elements(
		                            CASE WHEN jsonb_typeof(lb_config->'smart_routing'->'tiers') = 'array'
		                                 THEN lb_config->'smart_routing'->'tiers'
		                                 ELSE '[]'::jsonb
		                            END
		                        ) WITH ORDINALITY AS t(t, ord)), '{}'),
		       COALESCE((SELECT array_agg(m->>'registry_id' ORDER BY ord)
		                   FROM jsonb_array_elements(
		                            CASE WHEN jsonb_typeof(lb_config->'members') = 'array'
		                                 THEN lb_config->'members'
		                                 ELSE '[]'::jsonb
		                            END
		                        ) WITH ORDINALITY AS m(m, ord)), '{}')
		  FROM consumers
		 WHERE id = $1`
	var got lbConfigState
	if err := tx.QueryRow(ctx, query, id).Scan(
		&got.hasSmartRouting, &got.algorithm, &got.tierRegistries, &got.memberRegistries,
	); err != nil {
		t.Fatalf("read lb_config state for %s: %v", id, err)
	}
	if got.hasSmartRouting != want.hasSmartRouting {
		t.Fatalf("%s has smart_routing = %v, want %v", id, got.hasSmartRouting, want.hasSmartRouting)
	}
	if got.algorithm != want.algorithm {
		t.Fatalf("%s algorithm = %q, want %q", id, got.algorithm, want.algorithm)
	}
	if !slices.Equal(got.tierRegistries, want.tierRegistries) {
		t.Fatalf("%s tier registries = %v, want %v", id, got.tierRegistries, want.tierRegistries)
	}
	if !slices.Equal(got.memberRegistries, want.memberRegistries) {
		t.Fatalf("%s member registries = %v, want %v", id, got.memberRegistries, want.memberRegistries)
	}
}
