package migrations

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"gorm.io/gorm"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20240003_add_rule_type_to_forwarding_rules",
		Name: "Add rule_type enum column to forwarding_rules table",

		Up: func(db *gorm.DB) error {
			if err := db.Exec(`
				CREATE TYPE rule_type AS ENUM ('agent', 'endpoint');
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				ADD COLUMN rule_type rule_type NOT NULL DEFAULT 'endpoint';
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				UPDATE forwarding_rules
				SET rule_type = 'endpoint'
				WHERE rule_type IS NULL;
			`).Error; err != nil {
				return err
			}

			return nil
		},

		Down: func(db *gorm.DB) error {
			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				DROP COLUMN IF EXISTS rule_type;
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				DROP TYPE IF EXISTS rule_type;
			`).Error; err != nil {
				return err
			}

			return nil
		},
	})
}
