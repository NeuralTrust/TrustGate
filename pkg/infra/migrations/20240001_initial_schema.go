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
			// Ensure extension for gen_random_uuid()
			if err := db.Exec(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`).Error; err != nil {
				return err
			}

			// Enum for API keys
			if err := db.Exec(`
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subject_type') THEN
        CREATE TYPE subject_type AS ENUM ('gateway', 'policy');
    END IF;
END $$;`).Error; err != nil {
				return err
			}

			// Gateways
			if err := db.Exec(`
CREATE TABLE IF NOT EXISTS public.gateways (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    telemetry       JSONB,
    required_plugins JSONB,
    security_config JSONB,
    client_tls_config      JSONB,
    session_config  JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`).Error; err != nil {
				return err
			}

			// Upstreams
			if err := db.Exec(`
CREATE TABLE IF NOT EXISTS public.upstreams (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id       UUID NOT NULL REFERENCES public.gateways(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    algorithm        TEXT NOT NULL DEFAULT 'round-robin',
    targets          JSONB,
    embedding_config JSONB,
    health_checks    JSONB,
    tags             JSONB,
    websocket JSONB,
    proxy            JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`).Error; err != nil {
				return err
			}
			if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_gateway_upstream_name ON public.upstreams (name, gateway_id);`).Error; err != nil {
				return err
			}

			// Services
			if err := db.Exec(`
CREATE TABLE IF NOT EXISTS public.services (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id   UUID NOT NULL REFERENCES public.gateways(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    type         TEXT NOT NULL,
    description  TEXT,
    tags         JSONB,
    upstream_id  UUID NULL REFERENCES public.upstreams(id) ON DELETE SET NULL,
    host         TEXT,
    port         INTEGER,
    protocol     TEXT,
    path         TEXT,
    headers      JSONB,
    credentials  JSONB,
    stream       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`).Error; err != nil {
				return err
			}
			if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_gateway_service_name ON public.services (name, gateway_id);`).Error; err != nil {
				return err
			}

			// API Keys (IAM)
			if err := db.Exec(`
CREATE TABLE IF NOT EXISTS public.api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key          TEXT NOT NULL,
    name         TEXT,
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    subject_type subject_type NOT NULL,
    subject      UUID,
    policies     UUID[],
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`).Error; err != nil {
				return err
			}
			if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_keys_key ON public.api_keys (key);`).Error; err != nil {
				return err
			}

			// Forwarding Rules
			if err := db.Exec(`
CREATE TABLE IF NOT EXISTS public.forwarding_rules (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT,
    gateway_id     UUID NOT NULL REFERENCES public.gateways(id) ON DELETE CASCADE,
    service_id     UUID NOT NULL REFERENCES public.services(id) ON DELETE CASCADE,
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
);`).Error; err != nil {
				return err
			}

			return nil
		},
		Down: func(db *gorm.DB) error {
			// Drop in dependency order
			if err := db.Exec(`DROP TABLE IF EXISTS public.forwarding_rules;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`DROP TABLE IF EXISTS public.services;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`DROP TABLE IF EXISTS public.upstreams;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`DROP TABLE IF EXISTS public.api_keys;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`DROP TABLE IF EXISTS public.gateways;`).Error; err != nil {
				return err
			}
			if err := db.Exec(`
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subject_type') THEN
        DROP TYPE subject_type;
    END IF;
END $$;`).Error; err != nil {
				return err
			}
			return nil
		},
	})
}
