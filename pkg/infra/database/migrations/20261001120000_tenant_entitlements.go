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
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

const tenantEntitlementsMigrationID = "20261001120000_tenant_entitlements"

func init() {
	database.RegisterMigration(database.Migration{
		ID:   tenantEntitlementsMigrationID,
		Name: "store the plan caps once per tenant",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `
				CREATE TABLE IF NOT EXISTS tenant_entitlements (
					tenant_id       TEXT PRIMARY KEY,
					tier            TEXT NOT NULL,
					burst_per_min   INTEGER NOT NULL,
					quota_per_month INTEGER NOT NULL,
					max_instances   INTEGER NOT NULL,
					updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
				)`); err != nil {
				return err
			}
			return seedTenantEntitlementsFromGateways(ctx, tx, slog.Default())
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DROP TABLE IF EXISTS tenant_entitlements`)
			return err
		},
	})
}

// maxLoggedTenants bounds how many tenant ids a warning lists.
const maxLoggedTenants = 200

// stampedGateways selects, one row per gateway, the caps already stamped on it.
//
// Only gateways whose three caps are integral JSON numbers within 0..int32, and
// whose burst is at least 1 (the domain requires burst > 0: a burst of 0 would
// answer 429 to every request of the tenant), are seeded from. A cast of
// anything else would either abort the whole migration (a number past int32, a
// string) or silently round (1.5), and a migration that cannot run takes the
// process down with it. jsonb_typeof is checked in one
// step and the range in the next, because Postgres does not promise the order
// in which the conjuncts of a single WHERE are evaluated: a cast sitting beside
// its own guard can still run first.
const stampedGateways = `
	numbers AS (
		SELECT id, metadata->>'tenant_id' AS tenant_id, updated_at,
			COALESCE(NULLIF(entitlements->>'tier', ''), 'free') AS tier,
			CASE WHEN jsonb_typeof(entitlements->'burst_per_min') = 'number'
				THEN (entitlements->>'burst_per_min')::numeric END AS burst,
			CASE WHEN jsonb_typeof(entitlements->'quota_per_month') = 'number'
				THEN (entitlements->>'quota_per_month')::numeric END AS quota,
			CASE WHEN jsonb_typeof(entitlements->'max_instances') = 'number'
				THEN (entitlements->>'max_instances')::numeric END AS max_inst
		FROM gateways
		WHERE COALESCE(metadata->>'tenant_id', '') <> ''
	),
	valid AS (
		SELECT id, tenant_id, updated_at, tier,
			burst::int AS burst, quota::int AS quota, max_inst::int AS max_inst
		FROM numbers
		WHERE burst IS NOT NULL AND quota IS NOT NULL AND max_inst IS NOT NULL
		  AND burst = trunc(burst) AND quota = trunc(quota) AND max_inst = trunc(max_inst)
		  AND burst BETWEEN 1 AND 2147483647
		  AND quota BETWEEN 0 AND 2147483647
		  AND max_inst BETWEEN 0 AND 2147483647
	)`

// seedTenantEntitlementsFromGateways seeds a row per tenant from the caps already
// stamped on its gateways, so a tenant is metered against its plan from the
// first snapshot after the rollout instead of falling back to the per-gateway
// stamp.
//
// Gateways of one tenant can disagree (a restamp that raced a create, or one
// gateway that was never restamped). The most recently updated gateway is not a
// safe tiebreak: gateways.updated_at moves on any edit, not only on a stamp, so
// renaming a stale gateway would make its old caps win. Instead the tenant gets
// the largest caps any of its gateways carries: burst by maximum, the monthly
// quota and the instance cap by maximum too with 0 (unlimited) counting as the
// largest, and the tier of the gateway with the largest quota (ties broken by
// burst, then most recently updated, then id). A tenant is never silently
// downgraded by a stale sibling; the cost is that one upgraded and then
// left-behind gateway keeps the higher plan until the next restamp, which
// writes the real one. Tenants whose gateways disagreed, and gateways whose
// stamp was skipped as unusable, are logged.
//
// Rolling back. A release older than this one never reads or writes
// tenant_entitlements; it only stamps gateways. So a rollback that leaves the
// table in place leaves rows that go stale, and rolling forward again does not
// re-seed (ON CONFLICT DO NOTHING keeps them), so a stale row would win over
// fresher stamps. Either roll the schema back too (Down drops the table and the
// next Up re-seeds it from the gateways) or, after rolling forward, re-push the
// plans so the restamp re-asserts every row.
func seedTenantEntitlementsFromGateways(ctx context.Context, tx pgx.Tx, logger *slog.Logger) error {
	disagreeing, err := queryStrings(ctx, tx, `
		WITH `+stampedGateways+`
		SELECT tenant_id FROM valid
		GROUP BY tenant_id
		HAVING COUNT(DISTINCT (tier, burst, quota, max_inst)) > 1
		ORDER BY tenant_id`)
	if err != nil {
		return err
	}
	// A stamped gateway that did not make it into `valid`: the stamp is there
	// but unusable (partial, out of range, fractional, not a number).
	skipped, err := queryStrings(ctx, tx, `
		WITH `+stampedGateways+`
		SELECT DISTINCT n.tenant_id FROM numbers n
		JOIN gateways g ON g.id = n.id
		WHERE g.entitlements ?| array['burst_per_min', 'quota_per_month', 'max_instances']
		  AND NOT EXISTS (SELECT 1 FROM valid v WHERE v.id = n.id)
		ORDER BY n.tenant_id`)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		WITH `+stampedGateways+`,
		largest AS (
			SELECT tenant_id,
				MAX(burst) AS burst,
				CASE WHEN bool_or(quota = 0) THEN 0 ELSE MAX(quota) END AS quota,
				CASE WHEN bool_or(max_inst = 0) THEN 0 ELSE MAX(max_inst) END AS max_inst
			FROM valid
			GROUP BY tenant_id
		),
		tiers AS (
			SELECT DISTINCT ON (tenant_id) tenant_id, tier
			FROM valid
			ORDER BY tenant_id, (quota = 0) DESC, quota DESC, burst DESC, updated_at DESC, id
		)
		INSERT INTO tenant_entitlements (tenant_id, tier, burst_per_min, quota_per_month, max_instances)
		SELECT l.tenant_id, t.tier, l.burst, l.quota, l.max_inst
		FROM largest l
		JOIN tiers t USING (tenant_id)
		ON CONFLICT (tenant_id) DO NOTHING`); err != nil {
		return err
	}

	if len(disagreeing) > 0 {
		logger.Warn("tenant_entitlements seed: gateways of these tenants carried different stamped caps; the largest were kept",
			slog.String("migration", tenantEntitlementsMigrationID),
			slog.Int("tenants", len(disagreeing)),
			slog.Any("tenant_ids", firstN(disagreeing)))
	}
	if len(skipped) > 0 {
		logger.Warn("tenant_entitlements seed: some stamped caps were not integral numbers within 0..2147483647, or had a burst of 0, and were ignored",
			slog.String("migration", tenantEntitlementsMigrationID),
			slog.Int("tenants", len(skipped)),
			slog.Any("tenant_ids", firstN(skipped)))
	}
	return nil
}

func firstN(ids []string) []string {
	if len(ids) > maxLoggedTenants {
		return ids[:maxLoggedTenants]
	}
	return ids
}

func queryStrings(ctx context.Context, tx pgx.Tx, query string) ([]string, error) {
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
