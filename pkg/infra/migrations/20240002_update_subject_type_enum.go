package migrations

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"gorm.io/gorm"
)

// Migration to update subject_type enum: replace 'policy' with 'engine'
// Safely recreates the enum and migrates existing data.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20240002_update_subject_type_enum",
		Name: "Update subject_type enum to {'gateway','engine'} and migrate data",
		Up: func(db *gorm.DB) error {
			// Create the new enum with desired values
			if err := db.Exec(`
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subject_type_new') THEN
        CREATE TYPE subject_type_new AS ENUM ('gateway', 'engine');
    END IF;
END $$;`).Error; err != nil {
				return err
			}

			// Convert api_keys.subject_type to the new enum, mapping 'policy' -> 'engine'
			if err := db.Exec(`
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name='api_keys' AND column_name='subject_type'
    ) THEN
        ALTER TABLE api_keys 
        ALTER COLUMN subject_type TYPE subject_type_new 
        USING (CASE WHEN subject_type::text = 'policy' THEN 'engine' ELSE subject_type::text END)::subject_type_new;
    END IF;
END $$;`).Error; err != nil {
				return err
			}

			// Drop old enum and rename new one to subject_type
			if err := db.Exec(`
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subject_type') THEN
        DROP TYPE subject_type;
    END IF;
END $$;`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subject_type_new') THEN
        ALTER TYPE subject_type_new RENAME TO subject_type;
    END IF;
END $$;`).Error; err != nil {
				return err
			}

			return nil
		},
		Down: func(db *gorm.DB) error {
			// Recreate the old enum with values ('gateway','policy')
			if err := db.Exec(`
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subject_type_old') THEN
        CREATE TYPE subject_type_old AS ENUM ('gateway', 'policy');
    END IF;
END $$;`).Error; err != nil {
				return err
			}

			// Convert back mapping 'engine' -> 'policy'
			if err := db.Exec(`
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name='api_keys' AND column_name='subject_type'
    ) THEN
        ALTER TABLE api_keys 
        ALTER COLUMN subject_type TYPE subject_type_old 
        USING (CASE WHEN subject_type::text = 'engine' THEN 'policy' ELSE subject_type::text END)::subject_type_old;
    END IF;
END $$;`).Error; err != nil {
				return err
			}

			// Drop current enum and rename old one back to subject_type
			if err := db.Exec(`
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subject_type') THEN
        DROP TYPE subject_type;
    END IF;
END $$;`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subject_type_old') THEN
        ALTER TYPE subject_type_old RENAME TO subject_type;
    END IF;
END $$;`).Error; err != nil {
				return err
			}

			return nil
		},
	})
}
