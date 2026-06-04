package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260603140000_add_auth_key_hash",
		Name: "add auths key_hash column for api key reverse lookup",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE auths ADD COLUMN IF NOT EXISTS key_hash TEXT;

				UPDATE auths
				   SET key_hash = encode(sha256(convert_to(config->'api_key'->>'key', 'UTF8')), 'hex')
				 WHERE type = 'api_key'
				   AND key_hash IS NULL
				   AND config ? 'api_key'
				   AND config->'api_key'->>'key' IS NOT NULL;

				CREATE UNIQUE INDEX IF NOT EXISTS auths_key_hash_uniq
					ON auths (key_hash)
					WHERE type = 'api_key' AND key_hash IS NOT NULL;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DROP INDEX IF EXISTS auths_key_hash_uniq;
				ALTER TABLE auths DROP COLUMN IF EXISTS key_hash;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
