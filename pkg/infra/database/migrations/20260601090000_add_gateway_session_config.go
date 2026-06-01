package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260601090000_add_gateway_session_config",
		Name: "add gateway session_config column",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `ALTER TABLE gateways ADD COLUMN IF NOT EXISTS session_config JSONB;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `ALTER TABLE gateways DROP COLUMN IF EXISTS session_config;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
