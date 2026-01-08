package migrations

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"gorm.io/gorm"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20240004_create_tls_certs_table",
		Name: "Create tls_certs table for storing TLS certificates",

		Up: func(db *gorm.DB) error {
			if err := db.Exec(`
				CREATE TABLE IF NOT EXISTS tls_certs (
					id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
					gateway_id  UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
					host        TEXT NOT NULL,
					ca_cert     TEXT,
					client_cert TEXT,
					client_key  TEXT,
					created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					UNIQUE(gateway_id, host)
				);
			`).Error; err != nil {
				return err
			}

			// Create index for faster lookups by gateway_id
			if err := db.Exec(`
				CREATE INDEX IF NOT EXISTS idx_tls_certs_gateway_id 
				ON tls_certs (gateway_id);
			`).Error; err != nil {
				return err
			}

			// Create index for faster lookups by gateway_id and host
			if err := db.Exec(`
				CREATE INDEX IF NOT EXISTS idx_tls_certs_gateway_host 
				ON tls_certs (gateway_id, host);
			`).Error; err != nil {
				return err
			}

			return nil
		},

		Down: func(db *gorm.DB) error {
			return db.Exec(`DROP TABLE IF EXISTS tls_certs;`).Error
		},
	})
}


