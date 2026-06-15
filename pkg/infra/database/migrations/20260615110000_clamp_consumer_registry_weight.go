package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260615110000_clamp_consumer_registry_weight",
		Name: "clamp consumer_registry weights to the new 1..100 range",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				UPDATE consumer_registry SET weight = 100 WHERE weight > 100;
				UPDATE consumer_registry SET weight = 1 WHERE weight < 1;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		// Down is a no-op: clamping into 1..100 is lossy, so the pre-migration
		// weights cannot be reconstructed.
		Down: func(ctx context.Context, tx pgx.Tx) error {
			return nil
		},
	})
}
