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

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260618120000_rename_idp_to_oidc",
		Name: "rename idp to oidc",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE auths DROP CONSTRAINT IF EXISTS auths_type_check;
				UPDATE auths SET type = 'oidc' WHERE type = 'idp';
				UPDATE auths
				SET config = (config - 'idp') || jsonb_build_object('oidc', config->'idp')
				WHERE config ? 'idp';
				ALTER TABLE roles RENAME COLUMN idp_mapping TO oidc_mapping;
				ALTER TABLE auths ADD CONSTRAINT auths_type_check CHECK (type IN ('api_key','oauth2','oidc','mtls'));`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE auths DROP CONSTRAINT IF EXISTS auths_type_check;
				ALTER TABLE auths ADD CONSTRAINT auths_type_check CHECK (type IN ('api_key','oauth2','idp','mtls'));
				ALTER TABLE roles RENAME COLUMN oidc_mapping TO idp_mapping;
				UPDATE auths
				SET config = (config - 'oidc') || jsonb_build_object('idp', config->'oidc')
				WHERE config ? 'oidc';
				UPDATE auths SET type = 'idp' WHERE type = 'oidc';`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
