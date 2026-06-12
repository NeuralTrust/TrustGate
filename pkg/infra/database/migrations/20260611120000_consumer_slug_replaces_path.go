package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260611120000_consumer_slug_replaces_path",
		Name: "replace consumer custom path with an auto-generated slug",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS slug TEXT;
				UPDATE consumers
				   SET slug = substr(md5(id::text || clock_timestamp()::text), 1, 8)
				 WHERE slug IS NULL;
				ALTER TABLE consumers ALTER COLUMN slug SET NOT NULL;
				CREATE UNIQUE INDEX IF NOT EXISTS consumers_slug_unique_idx ON consumers (slug);
				ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_gateway_path_unique;
				DROP INDEX IF EXISTS consumers_gateway_path_unique;
				ALTER TABLE consumers DROP COLUMN IF EXISTS path;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS path TEXT NOT NULL DEFAULT '';
				DROP INDEX IF EXISTS consumers_slug_unique_idx;
				ALTER TABLE consumers DROP COLUMN IF EXISTS slug;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
