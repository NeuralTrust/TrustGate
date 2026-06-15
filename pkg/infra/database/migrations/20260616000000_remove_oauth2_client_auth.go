package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260616000000_remove_oauth2_client_auth",
		Name: "remove oauth2_client auth",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DELETE FROM auths WHERE type = 'oauth2_client';
				ALTER TABLE auths DROP CONSTRAINT IF EXISTS auths_type_check;
				ALTER TABLE auths ADD CONSTRAINT auths_type_check CHECK (type IN ('api_key','oauth2','idp','mtls'));`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE auths DROP CONSTRAINT IF EXISTS auths_type_check;
				ALTER TABLE auths ADD CONSTRAINT auths_type_check CHECK (type IN ('api_key','oauth2','oauth2_client','idp','mtls'));`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
