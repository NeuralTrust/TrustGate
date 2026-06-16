package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260616120000_add_gateway_metadata",
		Name: "add gateways.metadata for arbitrary key/value gateway metadata",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `ALTER TABLE gateways ADD COLUMN IF NOT EXISTS metadata JSONB;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `ALTER TABLE gateways DROP COLUMN IF EXISTS metadata;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
