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

// consumersLockTimeout bounds the wait for the ACCESS EXCLUSIVE lock: every
// consumer write and snapshot compile touches the table, so an ALTER queued
// behind a long one would queue all of them; failing fast lets the rollout retry.
const consumersLockTimeout = `SET LOCAL lock_timeout = '5s';`

// The unique name and slug only hold among live consumers, so a deleted one
// never blocks reusing them. The indexes keep their old names: the repository
// maps a slug conflict by the index name.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20261111120000_consumers_soft_delete",
		Name: "soft delete consumers",
		Up:   upConsumersSoftDelete,
		Down: downConsumersSoftDelete,
	})
}

func upConsumersSoftDelete(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, consumersLockTimeout+`
		ALTER TABLE consumers ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

		ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_gateway_name_unique;
		DROP INDEX IF EXISTS consumers_gateway_name_unique;
		CREATE UNIQUE INDEX consumers_gateway_name_unique
			ON consumers (gateway_id, name) WHERE deleted_at IS NULL;

		DROP INDEX IF EXISTS consumers_slug_unique_idx;
		CREATE UNIQUE INDEX consumers_slug_unique_idx
			ON consumers (slug) WHERE deleted_at IS NULL;

		CREATE INDEX IF NOT EXISTS consumers_gateway_live_idx
			ON consumers (gateway_id) WHERE deleted_at IS NULL;`)
	return err
}

// Down drops the history: deleted consumers would otherwise come back live and
// collide with the live ones that reused their name or slug. Their links went
// with the soft delete, so nothing cascades.
func downConsumersSoftDelete(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, consumersLockTimeout+`
		DO $$
		BEGIN
			IF EXISTS (SELECT 1 FROM pg_attribute
			            WHERE attrelid = 'consumers'::regclass
			              AND attname = 'deleted_at' AND NOT attisdropped) THEN
				DELETE FROM consumers WHERE deleted_at IS NOT NULL;
			END IF;
		END $$;

		DROP INDEX IF EXISTS consumers_gateway_live_idx;

		DROP INDEX IF EXISTS consumers_slug_unique_idx;
		CREATE UNIQUE INDEX consumers_slug_unique_idx ON consumers (slug);

		ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_gateway_name_unique;
		DROP INDEX IF EXISTS consumers_gateway_name_unique;
		ALTER TABLE consumers ADD CONSTRAINT consumers_gateway_name_unique UNIQUE (gateway_id, name);

		ALTER TABLE consumers DROP COLUMN IF EXISTS deleted_at;`)
	return err
}
