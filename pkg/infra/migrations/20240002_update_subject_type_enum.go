package migrations

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"gorm.io/gorm"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20240002_update_subject_type_enum",
		Name: "Update subject_type enum to {'gateway','engine'} and migrate data (simple SQL version)",

		Up: func(db *gorm.DB) error {
			if err := db.Exec(`
				CREATE TYPE subject_type_new AS ENUM ('gateway', 'engine');
			`).Error; err != nil {
				_ = db.Exec(`DROP TYPE IF EXISTS subject_type_new;`)
				if err := db.Exec(`
					CREATE TYPE subject_type_new AS ENUM ('gateway', 'engine');
				`).Error; err != nil {
					return err
				}
			}

			if err := db.Exec(`
				ALTER TABLE api_keys
				ALTER COLUMN subject_type TYPE subject_type_new
				USING (
					CASE 
						WHEN subject_type::text = 'policy' THEN 'engine'
						ELSE subject_type::text
					END
				)::subject_type_new;
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				DROP TYPE IF EXISTS subject_type;
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				ALTER TYPE subject_type_new RENAME TO subject_type;
			`).Error; err != nil {
				return err
			}

			return nil
		},

		Down: func(db *gorm.DB) error {
			if err := db.Exec(`
				CREATE TYPE subject_type_old AS ENUM ('gateway', 'policy');
			`).Error; err != nil {
				_ = db.Exec(`DROP TYPE IF EXISTS subject_type_old;`)
				if err := db.Exec(`
					CREATE TYPE subject_type_old AS ENUM ('gateway', 'policy');
				`).Error; err != nil {
					return err
				}
			}

			if err := db.Exec(`
				ALTER TABLE api_keys
				ALTER COLUMN subject_type TYPE subject_type_old
				USING (
					CASE 
						WHEN subject_type::text = 'engine' THEN 'policy'
						ELSE subject_type::text
					END
				)::subject_type_old;
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				DROP TYPE IF EXISTS subject_type;
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				ALTER TYPE subject_type_old RENAME TO subject_type;
			`).Error; err != nil {
				return err
			}

			return nil
		},
	})
}
