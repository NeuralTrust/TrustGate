package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260604120000_add_policy_description",
		Name: "add policies description column",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE policies ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE policies DROP COLUMN IF EXISTS description;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
