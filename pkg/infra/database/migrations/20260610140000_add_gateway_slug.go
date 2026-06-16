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

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

const addGatewaySlugDDL = `
	ALTER TABLE gateways ADD COLUMN IF NOT EXISTS slug TEXT;

	WITH normalized AS (
		SELECT
			id,
			COALESCE(NULLIF(trim(both '-' FROM regexp_replace(lower(name), '[^a-z0-9]+', '-', 'g')), ''), 'gateway') AS base
		FROM gateways
		WHERE slug IS NULL OR slug = ''
	),
	backfilled AS (
		SELECT
			id,
			COALESCE(NULLIF(trim(both '-' FROM left(base, 26)), ''), 'gateway') || '-' || id::text AS slug
		FROM normalized
	)
	UPDATE gateways
	   SET slug = backfilled.slug
	  FROM backfilled
	 WHERE gateways.id = backfilled.id;

	ALTER TABLE gateways ALTER COLUMN slug SET NOT NULL;
	CREATE UNIQUE INDEX IF NOT EXISTS gateways_slug_unique_idx ON gateways (slug);
	DO $$
	BEGIN
		IF NOT EXISTS (
			SELECT 1
			FROM pg_constraint
			WHERE conname = 'gateways_slug_check'
		) THEN
			ALTER TABLE gateways ADD CONSTRAINT gateways_slug_check CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$');
		END IF;
	END $$;`

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260610140000_add_gateway_slug",
		Name: "add gateway slug",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, addGatewaySlugDDL)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE gateways DROP CONSTRAINT IF EXISTS gateways_slug_check;
				DROP INDEX IF EXISTS gateways_slug_unique_idx;
				ALTER TABLE gateways DROP COLUMN IF EXISTS slug;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
