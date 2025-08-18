package migrations

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"gorm.io/gorm"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20250101_drop_unique_names",
		Name: "Drop unique indexes for upstream.name and service.name",
		Up: func(db *gorm.DB) error {
			if err := db.Exec(`DROP INDEX IF EXISTS public.idx_gateway_upstream_name;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`DROP INDEX IF EXISTS public.idx_gateway_service_name;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_gateway_upstream_name ON public.upstreams (name, gateway_id);`).Error; err != nil {
				return err
			}
			if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_gateway_service_name ON public.services (name, gateway_id);`).Error; err != nil {
				return err
			}
			return nil
		},
		Down: func(db *gorm.DB) error {
			if err := db.Exec(`DROP INDEX IF EXISTS public.idx_gateway_upstream_name;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`DROP INDEX IF EXISTS public.idx_gateway_service_name;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_upstream_name ON public.upstreams (name, gateway_id);`).Error; err != nil {
				return err
			}
			if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_service_name ON public.services (name, gateway_id);`).Error; err != nil {
				return err
			}
			return nil
		},
	})
}
