package migrations

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"gorm.io/gorm"
)

// Initial SQL schema to replace GORM AutoMigrate for core entities
// Tables: gateways, upstreams, services, api_keys, forwarding_rules
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20240001_initial_schema",
		Name: "Create core tables: gateways, upstreams, services, api_keys, forwarding_rules",

		Up: func(db *gorm.DB) error {
			// 1. Ensure pgcrypto extension
			if err := db.Exec(`
				CREATE EXTENSION IF NOT EXISTS pgcrypto;
			`).Error; err != nil {
				return err
			}

			// 2. Create enum type for api_keys.subject_type
			_ = db.Exec(`DROP TYPE IF EXISTS subject_type;`)
			if err := db.Exec(`
				CREATE TYPE subject_type AS ENUM ('gateway', 'policy');
			`).Error; err != nil {
				return err
			}

			// 3. Create gateways table
			if err := db.Exec(`
				CREATE TABLE IF NOT EXISTS gateways (
					id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
					name                TEXT NOT NULL,
					status              TEXT NOT NULL DEFAULT 'active',
					telemetry           JSONB,
					required_plugins    JSONB,
					security_config     JSONB,
					client_tls_config   JSONB,
					session_config      JSONB,
					created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);
			`).Error; err != nil {
				return err
			}

			// 4. Create upstreams table
			if err := db.Exec(`
				CREATE TABLE IF NOT EXISTS upstreams (
					id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
					gateway_id       UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
					name             TEXT NOT NULL,
					algorithm        TEXT NOT NULL DEFAULT 'round-robin',
					targets          JSONB,
					embedding_config JSONB,
					health_checks    JSONB,
					tags             JSONB,
					websocket        JSONB,
					proxy            JSONB,
					created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				CREATE INDEX IF NOT EXISTS idx_gateway_upstream_name 
				ON upstreams (name, gateway_id);
			`).Error; err != nil {
				return err
			}

			// 5. Create services table
			if err := db.Exec(`
				CREATE TABLE IF NOT EXISTS services (
					id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
					gateway_id   UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
					name         TEXT NOT NULL,
					type         TEXT NOT NULL,
					description  TEXT,
					tags         JSONB,
					upstream_id  UUID NULL REFERENCES upstreams(id) ON DELETE SET NULL,
					host         TEXT,
					port         INTEGER,
					protocol     TEXT,
					path         TEXT,
					headers      JSONB,
					credentials  JSONB,
					stream       BOOLEAN NOT NULL DEFAULT FALSE,
					created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				CREATE INDEX IF NOT EXISTS idx_gateway_service_name 
				ON services (name, gateway_id);
			`).Error; err != nil {
				return err
			}

			// 6. Create api_keys table
			if err := db.Exec(`
				CREATE TABLE IF NOT EXISTS api_keys (
					id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
					key          TEXT NOT NULL,
					name         TEXT,
					active       BOOLEAN NOT NULL DEFAULT TRUE,
					subject_type subject_type NOT NULL,
					subject      UUID,
					policies     UUID[],
					expires_at   TIMESTAMPTZ,
					created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);
			`).Error; err != nil {
				return err
			}

			if err := db.Exec(`
				CREATE INDEX IF NOT EXISTS idx_api_keys_key 
				ON api_keys (key);
			`).Error; err != nil {
				return err
			}

			// 7. Create forwarding_rules table
			if err := db.Exec(`
				CREATE TABLE IF NOT EXISTS forwarding_rules (
					id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
					name           TEXT,
					gateway_id     UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
					service_id     UUID NOT NULL REFERENCES services(id) ON DELETE CASCADE,
					path           TEXT NOT NULL,
					methods        JSONB,
					headers        JSONB,
					strip_path     BOOLEAN NOT NULL DEFAULT FALSE,
					preserve_host  BOOLEAN NOT NULL DEFAULT FALSE,
					plugin_chain   JSONB,
					active         BOOLEAN NOT NULL DEFAULT TRUE,
					public         BOOLEAN NOT NULL DEFAULT FALSE,
					retry_attempts INTEGER NOT NULL DEFAULT 1,
					trust_lens     JSONB,
					created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);
			`).Error; err != nil {
				return err
			}

			return nil
		},

		Down: func(db *gorm.DB) error {
			// Drop in dependency order
			if err := db.Exec(`DROP TABLE IF EXISTS forwarding_rules;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`DROP TABLE IF EXISTS services;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`DROP TABLE IF EXISTS upstreams;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`DROP TABLE IF EXISTS api_keys;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`DROP TABLE IF EXISTS gateways;`).Error; err != nil {
				return err
			}

			// Drop enum type
			if err := db.Exec(`
				DROP TYPE IF EXISTS subject_type;
			`).Error; err != nil {
				return err
			}

			return nil
		},
	})
}
