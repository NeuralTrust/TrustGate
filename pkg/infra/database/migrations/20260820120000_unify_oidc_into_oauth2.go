// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package migrations

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260820120000_unify_oidc_into_oauth2",
		Name: "unify oidc auths into oauth2",
		Up:   upUnifyOIDCIntoOAuth2,
		Down: downUnifyOIDCIntoOAuth2,
	})
}

func upUnifyOIDCIntoOAuth2(ctx context.Context, tx pgx.Tx) error {
	// The marker rows must be written before the type flip, or the predicate
	// selecting them is already gone.
	const ddl = `
		CREATE TABLE IF NOT EXISTS auths_oidc_migration (
			auth_id     UUID PRIMARY KEY,
			migrated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		INSERT INTO auths_oidc_migration (auth_id)
		SELECT id FROM auths WHERE type = 'oidc'
		ON CONFLICT DO NOTHING;

		ALTER TABLE auths DROP CONSTRAINT IF EXISTS auths_type_check;

		UPDATE auths
		SET config = (config - 'oidc') || jsonb_build_object('oauth2', config -> 'oidc')
		WHERE type = 'oidc' AND config ? 'oidc';

		UPDATE auths SET type = 'oauth2' WHERE type = 'oidc';

		ALTER TABLE auths ADD CONSTRAINT auths_type_check CHECK (type IN ('api_key','oauth2','mtls'));`
	if _, err := tx.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("unify oidc into oauth2: %w", err)
	}
	return nil
}

func downUnifyOIDCIntoOAuth2(ctx context.Context, tx pgx.Tx) error {
	const widen = `
		ALTER TABLE auths DROP CONSTRAINT IF EXISTS auths_type_check;
		ALTER TABLE auths ADD CONSTRAINT auths_type_check CHECK (type IN ('api_key','oauth2','oidc','mtls'));`
	if _, err := tx.Exec(ctx, widen); err != nil {
		return fmt.Errorf("widen auth type constraint: %w", err)
	}

	var hasMarkers bool
	if err := tx.QueryRow(ctx,
		`SELECT to_regclass('auths_oidc_migration') IS NOT NULL`,
	).Scan(&hasMarkers); err != nil {
		return fmt.Errorf("look up oidc migration markers: %w", err)
	}
	if !hasMarkers {
		return nil
	}

	// Only the recorded rows are demoted: an auth created natively as oauth2
	// must never become oidc.
	const demote = `
		UPDATE auths AS a
		SET config = (a.config - 'oauth2') || jsonb_build_object('oidc', a.config -> 'oauth2')
		FROM auths_oidc_migration AS m
		WHERE a.id = m.auth_id AND a.config ? 'oauth2';

		UPDATE auths AS a
		SET type = 'oidc'
		FROM auths_oidc_migration AS m
		WHERE a.id = m.auth_id;

		DROP TABLE IF EXISTS auths_oidc_migration;`
	if _, err := tx.Exec(ctx, demote); err != nil {
		return fmt.Errorf("demote migrated oidc auths: %w", err)
	}
	return nil
}
