package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260603100000_rename_backends_to_registries",
		Name: "rename backends table and consumer_backend junction to registries",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DO $rename$
				BEGIN
					IF to_regclass('public.backends') IS NOT NULL THEN
						ALTER TABLE backends RENAME TO registries;
						ALTER TABLE registries RENAME CONSTRAINT backends_gateway_name_unique TO registries_gateway_name_unique;
						ALTER INDEX backends_gateway_id_idx RENAME TO registries_gateway_id_idx;
						ALTER INDEX backends_name_lower_idx RENAME TO registries_name_lower_idx;
					END IF;

					IF to_regclass('public.consumer_backend') IS NOT NULL THEN
						ALTER TABLE consumer_backend RENAME TO consumer_registry;
						ALTER TABLE consumer_registry RENAME COLUMN backend_id TO registry_id;
						ALTER INDEX consumer_backend_backend_idx RENAME TO consumer_registry_registry_idx;
						ALTER TABLE consumer_registry RENAME CONSTRAINT consumer_backend_backend_id_fkey TO consumer_registry_registry_id_fkey;
					END IF;
				END
				$rename$;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DO $rename$
				BEGIN
					IF to_regclass('public.consumer_registry') IS NOT NULL THEN
						ALTER TABLE consumer_registry RENAME CONSTRAINT consumer_registry_registry_id_fkey TO consumer_backend_backend_id_fkey;
						ALTER INDEX consumer_registry_registry_idx RENAME TO consumer_backend_backend_idx;
						ALTER TABLE consumer_registry RENAME COLUMN registry_id TO backend_id;
						ALTER TABLE consumer_registry RENAME TO consumer_backend;
					END IF;

					IF to_regclass('public.registries') IS NOT NULL
					   AND to_regclass('public.backends') IS NULL THEN
						ALTER INDEX registries_name_lower_idx RENAME TO backends_name_lower_idx;
						ALTER INDEX registries_gateway_id_idx RENAME TO backends_gateway_id_idx;
						ALTER TABLE registries RENAME CONSTRAINT registries_gateway_name_unique TO backends_gateway_name_unique;
						ALTER TABLE registries RENAME TO backends;
					END IF;
				END
				$rename$;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
