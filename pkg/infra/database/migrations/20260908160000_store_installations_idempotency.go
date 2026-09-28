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

const storeInstallationsIdempotencyIndex = "uq_store_installations_logical_instance"

const storeInstallationsIdempotencyUp = `
	WITH ranked AS (
		SELECT id,
		       row_number() OVER (
				PARTITION BY gateway_id,
				             principal_sub,
				             catalog_code,
				             COALESCE(registry_id, '00000000-0000-0000-0000-000000000000'::uuid),
				             COALESCE(config, '{}'::jsonb)
				ORDER BY CASE status
				           WHEN 'installed' THEN 0
				           WHEN 'pending_approval' THEN 1
				           ELSE 2
				         END,
				         created_at,
				         id
		       ) AS position
		  FROM store_installations
	)
	DELETE FROM store_installations AS installations
	 USING ranked
	 WHERE installations.id = ranked.id
	   AND ranked.position > 1;

	CREATE UNIQUE INDEX IF NOT EXISTS ` + storeInstallationsIdempotencyIndex + `
		ON store_installations (
			gateway_id,
			principal_sub,
			catalog_code,
			COALESCE(registry_id, '00000000-0000-0000-0000-000000000000'::uuid),
			COALESCE(config, '{}'::jsonb)
		);`

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260908160000_store_installations_idempotency",
		Name: "enforce idempotency for logical Store installation instances",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, storeInstallationsIdempotencyUp)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DROP INDEX IF EXISTS `+storeInstallationsIdempotencyIndex+`;`)
			return err
		},
	})
}
