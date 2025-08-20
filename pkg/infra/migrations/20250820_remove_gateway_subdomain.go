package migrations

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"gorm.io/gorm"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20250820_remove_gateway_subdomain",
		Name: "Remove subdomain field and unique constraint from gateways table",
		Up: func(db *gorm.DB) error {
			// Drop the unique constraint on subdomain first
			if err := db.Exec(`DROP INDEX IF EXISTS public.idx_public_gateways_subdomain;`).Error; err != nil {
				return err
			}
			
			// Remove the subdomain column
			if err := db.Exec(`ALTER TABLE public.gateways DROP COLUMN IF EXISTS subdomain;`).Error; err != nil {
				return err
			}
			
			return nil
		},
		Down: func(db *gorm.DB) error {
			// Add back the subdomain column
			if err := db.Exec(`ALTER TABLE public.gateways ADD COLUMN IF NOT EXISTS subdomain VARCHAR(255);`).Error; err != nil {
				return err
			}
			
			// Recreate the unique constraint (note: this might fail if there are duplicate subdomains)
			if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_public_gateways_subdomain ON public.gateways (subdomain);`).Error; err != nil {
				return err
			}
			
			return nil
		},
	})
}