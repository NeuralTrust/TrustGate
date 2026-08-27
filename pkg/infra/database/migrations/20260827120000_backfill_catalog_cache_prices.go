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

// 20260826120000_add_catalog_cache_prices added the two cache price columns as
// plain nullable TEXT, so every row that already existed got NULL. The reader
// scans them into `string`, which pgx refuses to fill from NULL, and the whole
// catalog listing failed for any provider owning a pre-existing row — including
// disabled ones, which ListModelsByProviderCode still selects.
//
// The writer only ever sends a Go string, so NULL was never a value the domain
// could produce. Backfilling and closing the column matches the schema to that:
// the empty string is what "no cache price" already means everywhere else.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260827120000_backfill_catalog_cache_prices",
		Name: "backfill models_catalog cache prices and forbid NULL",
		Up:   upBackfillCatalogCachePrices,
		Down: downBackfillCatalogCachePrices,
	})
}

func upBackfillCatalogCachePrices(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		UPDATE models_catalog
		   SET cache_read_price  = COALESCE(cache_read_price, ''),
		       cache_write_price = COALESCE(cache_write_price, '')
		 WHERE cache_read_price IS NULL
		    OR cache_write_price IS NULL;

		ALTER TABLE models_catalog
			ALTER COLUMN cache_read_price  SET DEFAULT '',
			ALTER COLUMN cache_write_price SET DEFAULT '';

		ALTER TABLE models_catalog
			ALTER COLUMN cache_read_price  SET NOT NULL,
			ALTER COLUMN cache_write_price SET NOT NULL;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

// Down only reopens the columns. The backfilled empty strings stay: they are
// indistinguishable from what the writer produces, so there is nothing to undo.
func downBackfillCatalogCachePrices(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE models_catalog
			ALTER COLUMN cache_read_price  DROP NOT NULL,
			ALTER COLUMN cache_write_price DROP NOT NULL;

		ALTER TABLE models_catalog
			ALTER COLUMN cache_read_price  DROP DEFAULT,
			ALTER COLUMN cache_write_price DROP DEFAULT;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
