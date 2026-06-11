package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260611150000_consumer_registry_cascade_on_registry_delete",
		Name: "cascade consumer relation rows when a registry or auth is deleted",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumer_registry DROP CONSTRAINT IF EXISTS consumer_registry_registry_id_fkey;
				ALTER TABLE consumer_registry ADD CONSTRAINT consumer_registry_registry_id_fkey
					FOREIGN KEY (registry_id) REFERENCES registries(id) ON DELETE CASCADE;
				ALTER TABLE consumer_auth DROP CONSTRAINT IF EXISTS consumer_auth_auth_id_fkey;
				ALTER TABLE consumer_auth ADD CONSTRAINT consumer_auth_auth_id_fkey
					FOREIGN KEY (auth_id) REFERENCES auths(id) ON DELETE CASCADE;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumer_registry DROP CONSTRAINT IF EXISTS consumer_registry_registry_id_fkey;
				ALTER TABLE consumer_registry ADD CONSTRAINT consumer_registry_registry_id_fkey
					FOREIGN KEY (registry_id) REFERENCES registries(id) ON DELETE RESTRICT;
				ALTER TABLE consumer_auth DROP CONSTRAINT IF EXISTS consumer_auth_auth_id_fkey;
				ALTER TABLE consumer_auth ADD CONSTRAINT consumer_auth_auth_id_fkey
					FOREIGN KEY (auth_id) REFERENCES auths(id) ON DELETE RESTRICT;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
