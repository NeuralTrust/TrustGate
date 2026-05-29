package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260528113134_create_initial_schema",
		Name: "create initial schema",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				CREATE TABLE gateways (
					id          UUID PRIMARY KEY,
					name        TEXT NOT NULL,
					status      TEXT NOT NULL DEFAULT 'active',
					telemetry   JSONB,
					client_tls  JSONB,
					created_at  TIMESTAMPTZ NOT NULL,
					updated_at  TIMESTAMPTZ NOT NULL,
					CONSTRAINT gateways_name_unique UNIQUE (name)
				);
				CREATE INDEX gateways_name_lower_idx ON gateways (lower(name));

				CREATE TABLE backends (
					id                UUID PRIMARY KEY,
					gateway_id        UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
					name              TEXT NOT NULL,
					algorithm         TEXT NOT NULL DEFAULT 'round-robin',
					targets           JSONB NOT NULL DEFAULT '[]'::jsonb,
					embedding_config  JSONB,
					health_checks     JSONB,
					created_at        TIMESTAMPTZ NOT NULL,
					updated_at        TIMESTAMPTZ NOT NULL,
					CONSTRAINT backends_gateway_name_unique UNIQUE (gateway_id, name)
				);
				CREATE INDEX backends_gateway_id_idx ON backends (gateway_id);
				CREATE INDEX backends_name_lower_idx ON backends (lower(name));

				CREATE TABLE consumers (
					id              UUID PRIMARY KEY,
					gateway_id      UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
					name            TEXT NOT NULL,
					type            TEXT NOT NULL DEFAULT 'LLM',
					path            TEXT NOT NULL,
					paths           JSONB NOT NULL DEFAULT '[]'::jsonb,
					methods         JSONB NOT NULL DEFAULT '["POST"]'::jsonb,
					headers         JSONB NOT NULL DEFAULT '{}'::jsonb,
					strip_path      BOOLEAN NOT NULL DEFAULT FALSE,
					preserve_host   BOOLEAN NOT NULL DEFAULT FALSE,
					active          BOOLEAN NOT NULL DEFAULT TRUE,
					public          BOOLEAN NOT NULL DEFAULT FALSE,
					retry_attempts  INTEGER NOT NULL DEFAULT 1,
					created_at      TIMESTAMPTZ NOT NULL,
					updated_at      TIMESTAMPTZ NOT NULL,
					CONSTRAINT consumers_gateway_name_unique UNIQUE (gateway_id, name),
					CONSTRAINT consumers_type_check          CHECK (type IN ('LLM','MCP','A2A'))
				);
				CREATE INDEX consumers_gateway_id_idx ON consumers (gateway_id);
				CREATE INDEX consumers_name_lower_idx ON consumers (lower(name));

				CREATE TABLE consumer_backend (
					consumer_id UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
					backend_id  UUID NOT NULL REFERENCES backends(id) ON DELETE RESTRICT,
					PRIMARY KEY (consumer_id, backend_id)
				);
				CREATE INDEX consumer_backend_backend_idx ON consumer_backend (backend_id);

				CREATE TABLE policies (
					id          UUID PRIMARY KEY,
					gateway_id  UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
					name        TEXT NOT NULL,
					plugins     JSONB NOT NULL DEFAULT '[]'::jsonb,
					created_at  TIMESTAMPTZ NOT NULL,
					updated_at  TIMESTAMPTZ NOT NULL,
					CONSTRAINT policies_gateway_name_unique UNIQUE (gateway_id, name)
				);
				CREATE INDEX policies_gateway_id_idx ON policies (gateway_id);
				CREATE INDEX policies_name_lower_idx ON policies (lower(name));`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DROP TABLE IF EXISTS policies;
				DROP TABLE IF EXISTS consumer_backend;
				DROP TABLE IF EXISTS consumers;
				DROP TABLE IF EXISTS backends;
				DROP TABLE IF EXISTS gateways;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
