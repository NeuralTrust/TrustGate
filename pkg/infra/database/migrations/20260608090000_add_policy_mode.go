package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260608090000_add_policy_mode",
		Name: "add policies mode column",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE policies ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'enforce';`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE policies DROP COLUMN IF EXISTS mode;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
