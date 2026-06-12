package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260610130000_add_vault_credentials",
		Name: "add vault_credentials for forwarded third-party tokens",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				CREATE TABLE IF NOT EXISTS vault_credentials (
					id UUID PRIMARY KEY,
					gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
					principal_sub TEXT NOT NULL,
					provider TEXT NOT NULL,
					account_ref TEXT NOT NULL DEFAULT '',
					access_token TEXT NOT NULL,
					refresh_token TEXT NOT NULL DEFAULT '',
					scopes JSONB,
					expires_at TIMESTAMPTZ,
					created_at TIMESTAMPTZ NOT NULL,
					updated_at TIMESTAMPTZ NOT NULL,
					UNIQUE (gateway_id, principal_sub, provider)
				);
				CREATE INDEX IF NOT EXISTS idx_vault_credentials_principal
					ON vault_credentials (gateway_id, principal_sub);`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DROP TABLE IF EXISTS vault_credentials;`)
			return err
		},
	})
}
