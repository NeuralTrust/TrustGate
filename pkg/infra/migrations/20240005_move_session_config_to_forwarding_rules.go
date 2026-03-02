package migrations

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"gorm.io/gorm"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20240005_move_session_config_to_forwarding_rules",
		Name: "Move session_config from gateways to forwarding_rules",

		Up: func(db *gorm.DB) error {
			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				ADD COLUMN IF NOT EXISTS session_config JSONB;
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				ALTER TABLE gateways
				DROP COLUMN IF EXISTS session_config;
			`).Error; err != nil {
				return err
			}

			return nil
		},

		Down: func(db *gorm.DB) error {
			if err := db.Exec(`
				ALTER TABLE gateways
				ADD COLUMN IF NOT EXISTS session_config JSONB;
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				DROP COLUMN IF EXISTS session_config;
			`).Error; err != nil {
				return err
			}

			return nil
		},
	})
}
