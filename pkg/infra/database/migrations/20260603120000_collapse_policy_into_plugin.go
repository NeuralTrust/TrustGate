package migrations

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260603120000_collapse_policy_into_plugin",
		Name: "collapse policy plugins array into a 1:1 plugin policy",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DROP TABLE IF EXISTS consumer_policy;
				DROP TABLE IF EXISTS policies;

				CREATE TABLE policies (
					id          UUID PRIMARY KEY,
					gateway_id  UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
					name        TEXT NOT NULL,
					slug        TEXT NOT NULL,
					enabled     BOOLEAN NOT NULL DEFAULT TRUE,
					priority    INTEGER NOT NULL DEFAULT 0,
					parallel    BOOLEAN NOT NULL DEFAULT FALSE,
					settings    JSONB NOT NULL DEFAULT '{}'::jsonb,
					stages      JSONB NOT NULL DEFAULT '[]'::jsonb,
					created_at  TIMESTAMPTZ NOT NULL,
					updated_at  TIMESTAMPTZ NOT NULL,
					CONSTRAINT policies_gateway_name_unique UNIQUE (gateway_id, name)
				);
				CREATE INDEX policies_gateway_id_idx ON policies (gateway_id);
				CREATE INDEX policies_name_lower_idx ON policies (lower(name));

				CREATE TABLE consumer_policy (
					consumer_id UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
					policy_id   UUID NOT NULL REFERENCES policies(id) ON DELETE RESTRICT,
					PRIMARY KEY (consumer_id, policy_id)
				);
				CREATE INDEX consumer_policy_policy_idx ON consumer_policy (policy_id);`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DROP TABLE IF EXISTS consumer_policy;
				DROP TABLE IF EXISTS policies;

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
				CREATE INDEX policies_name_lower_idx ON policies (lower(name));

				CREATE TABLE consumer_policy (
					consumer_id UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
					policy_id   UUID NOT NULL REFERENCES policies(id) ON DELETE RESTRICT,
					PRIMARY KEY (consumer_id, policy_id)
				);
				CREATE INDEX consumer_policy_policy_idx ON consumer_policy (policy_id);`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
