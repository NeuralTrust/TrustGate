package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260611100000_add_gateway_domain",
		Name: "add gateways.domain for host-based gateway routing",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE gateways ADD COLUMN IF NOT EXISTS domain TEXT NOT NULL DEFAULT '';
				CREATE UNIQUE INDEX IF NOT EXISTS gateways_domain_unique
					ON gateways (domain) WHERE domain <> '';`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DROP INDEX IF EXISTS gateways_domain_unique;
				ALTER TABLE gateways DROP COLUMN IF EXISTS domain;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
