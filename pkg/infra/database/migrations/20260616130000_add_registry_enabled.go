package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260616130000_add_registry_enabled",
		Name: "add registries.enabled to toggle registries out of live traffic",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `ALTER TABLE registries ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `ALTER TABLE registries DROP COLUMN IF EXISTS enabled;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
