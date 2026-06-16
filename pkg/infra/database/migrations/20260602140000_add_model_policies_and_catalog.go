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

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260602140000_add_model_policies_and_catalog",
		Name: "add consumer model_policies and provider/model catalogs",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS model_policies JSONB;

				CREATE TABLE providers_catalog (
					id           UUID PRIMARY KEY,
					code         TEXT NOT NULL UNIQUE,
					display_name TEXT NOT NULL,
					wire_format  TEXT NOT NULL,
					source       TEXT NOT NULL DEFAULT 'manual',
					metadata     JSONB,
					created_at   TIMESTAMPTZ NOT NULL,
					updated_at   TIMESTAMPTZ NOT NULL
				);

				CREATE TABLE models_catalog (
					id             UUID PRIMARY KEY,
					provider_id    UUID NOT NULL REFERENCES providers_catalog(id) ON DELETE CASCADE,
					slug           TEXT NOT NULL,
					external_id    TEXT,
					display_name   TEXT,
					context_window INT,
					max_output     INT,
					input_price    TEXT,
					output_price   TEXT,
					capabilities   JSONB,
					enabled        BOOLEAN NOT NULL DEFAULT TRUE,
					source         TEXT NOT NULL DEFAULT 'manual',
					created_at     TIMESTAMPTZ NOT NULL,
					updated_at     TIMESTAMPTZ NOT NULL,
					CONSTRAINT models_catalog_provider_slug_unique UNIQUE (provider_id, slug)
				);
				CREATE INDEX models_catalog_provider_id_idx ON models_catalog (provider_id);`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DROP TABLE IF EXISTS models_catalog;
				DROP TABLE IF EXISTS providers_catalog;
				ALTER TABLE consumers DROP COLUMN IF EXISTS model_policies;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
