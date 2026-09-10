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

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

// RUN-1501 made Consumer.Validate check smart-routing tier registry ids even
// when the pool is disabled, which retroactively rejects the rows this ticket's
// bug created: `lb_config.enabled = false` carrying a tier on a registry that
// was deleted without pruning. An operator hitting one cannot escape it through
// the API — PATCHing only `name` keeps the stored lb_config and fails, and
// sending `lb_config: null` is indistinguishable from omitting it — so the fix
// has to be applied for them, once, here.
//
// It applies the same drop logic as Consumer.PruneRegistry: unknown tiers go; a
// ladder that loses its cheapest tier, or all of them, goes whole and the pool
// falls back to round-robin rather than silently promoting the cheapest score
// band to the pricier survivor. "Known" mirrors Consumer.knownRegistryIDs: a
// consumer_registry row, or a step in the consumer's fallback chain. Pool
// members are left alone; Validate never rejected those, so rewriting them here
// would change configurations that still work.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260910130000_prune_dangling_smart_routing_tiers",
		Name: "drop consumer smart-routing tiers whose registry is gone",
		Up:   upPruneDanglingSmartRoutingTiers,
		Down: downPruneDanglingSmartRoutingTiers,
	})
}

const pruneDanglingSmartRoutingTiersDDL = `
	WITH tier AS (
		SELECT c.id AS consumer_id,
		       t.ord,
		       t.tier,
		       CASE WHEN jsonb_typeof(t.tier->'min_score') = 'number'
		            THEN (t.tier->>'min_score')::numeric
		            ELSE 0
		       END AS min_score,
		       (
		           t.tier->>'registry_id' IS NOT NULL
		       AND t.tier->>'registry_id' <> ''
		       AND t.tier->>'registry_id' <> '00000000-0000-0000-0000-000000000000'
		       AND (
		               EXISTS (
		                   SELECT 1
		                     FROM consumer_registry cr
		                    WHERE cr.consumer_id = c.id
		                      AND cr.registry_id::text = t.tier->>'registry_id'
		               )
		            OR COALESCE(c.fallback->'chain', '[]'::jsonb) @> to_jsonb(t.tier->>'registry_id')
		           )
		       ) AS known
		  FROM consumers c
		  CROSS JOIN LATERAL jsonb_array_elements(
		           CASE WHEN jsonb_typeof(c.lb_config->'smart_routing'->'tiers') = 'array'
		                THEN c.lb_config->'smart_routing'->'tiers'
		                ELSE '[]'::jsonb
		           END
		       ) WITH ORDINALITY AS t(tier, ord)
	),
	affected AS (
		SELECT consumer_id,
		       jsonb_agg(tier ORDER BY ord) FILTER (WHERE known) AS kept,
		       min(min_score) AS old_floor,
		       min(min_score) FILTER (WHERE known) AS new_floor
		  FROM tier
		 GROUP BY consumer_id
		HAVING bool_or(NOT known)
	)
	UPDATE consumers c
	   SET lb_config = CASE
	           WHEN a.kept IS NULL OR a.new_floor > a.old_floor THEN
	               CASE WHEN c.lb_config->>'algorithm' = 'smart-routing'
	                    THEN jsonb_set(c.lb_config - 'smart_routing', '{algorithm}', '"round-robin"')
	                    ELSE c.lb_config - 'smart_routing'
	               END
	           ELSE jsonb_set(c.lb_config, '{smart_routing,tiers}', a.kept)
	       END,
	       updated_at = NOW()
	  FROM affected a
	 WHERE c.id = a.consumer_id;`

func upPruneDanglingSmartRoutingTiers(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, pruneDanglingSmartRoutingTiersDDL)
	return err
}

// Down is a no-op: the dropped tiers pointed at registries that no longer exist,
// so there is nothing to restore them to.
func downPruneDanglingSmartRoutingTiers(_ context.Context, _ pgx.Tx) error {
	return nil
}
