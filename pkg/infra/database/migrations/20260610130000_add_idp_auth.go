package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260610130000_add_idp_auth",
		Name: "add idp auth",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE auths DROP CONSTRAINT IF EXISTS auths_type_check;
				ALTER TABLE auths ADD CONSTRAINT auths_type_check CHECK (type IN ('api_key','oauth2','idp','mtls'));`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE auths DROP CONSTRAINT IF EXISTS auths_type_check;
				ALTER TABLE auths ADD CONSTRAINT auths_type_check CHECK (type IN ('api_key','oauth2','mtls'));`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
