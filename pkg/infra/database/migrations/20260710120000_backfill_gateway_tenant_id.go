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

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260710120000_backfill_gateway_tenant_id",
		Name: "backfill gateways.metadata.tenant_id from legacy team_id and drop team_id",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// Older gateways were created carrying only the legacy client key
			// team_id (same UUID as the tenant). Tenant partitioning reads
			// metadata.tenant_id, so seed it from team_id where it is missing or
			// empty, then drop team_id everywhere. Both statements are guarded on
			// the key's presence, so the migration is idempotent.
			const backfill = `
				UPDATE gateways
				SET metadata = jsonb_set(metadata, '{tenant_id}', metadata -> 'team_id', true)
				WHERE metadata ? 'team_id'
				  AND COALESCE(NULLIF(metadata ->> 'tenant_id', ''), '') = '';`
			if _, err := tx.Exec(ctx, backfill); err != nil {
				return err
			}

			const dropLegacy = `
				UPDATE gateways
				SET metadata = metadata - 'team_id'
				WHERE metadata ? 'team_id';`
			_, err := tx.Exec(ctx, dropLegacy)
			return err
		},
		Down: func(_ context.Context, _ pgx.Tx) error {
			return nil
		},
	})
}
