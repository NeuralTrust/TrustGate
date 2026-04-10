package migrations

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"gorm.io/gorm"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20240006_add_paths_to_forwarding_rules",
		Name: "Add paths JSONB column to forwarding_rules",

		Up: func(db *gorm.DB) error {
			return db.Exec(`
				ALTER TABLE forwarding_rules
				ADD COLUMN IF NOT EXISTS paths JSONB;
			`).Error
		},

		Down: func(db *gorm.DB) error {
			return db.Exec(`
				ALTER TABLE forwarding_rules
				DROP COLUMN IF EXISTS paths;
			`).Error
		},
	})
}
