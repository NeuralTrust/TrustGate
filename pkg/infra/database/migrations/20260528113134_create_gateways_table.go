package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260528113134_create_gateways_table",
		Name: "create gateways table",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				CREATE TABLE gateways (
					id          UUID PRIMARY KEY,
					name        TEXT NOT NULL,
					description TEXT NOT NULL DEFAULT '',
					created_at  TIMESTAMPTZ NOT NULL,
					updated_at  TIMESTAMPTZ NOT NULL,
					CONSTRAINT gateways_name_unique UNIQUE (name)
				);
				CREATE INDEX gateways_name_lower_idx ON gateways (lower(name));`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DROP TABLE IF EXISTS gateways;`)
			return err
		},
	})
}
