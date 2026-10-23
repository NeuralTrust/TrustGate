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

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20261022120000_add_auth_key_group",
		Name: "let a user hold one personal key per directory group as well as their own",
		Up:   upAddAuthKeyGroup,
		Down: downAddAuthKeyGroup,
	})
}

// upAddAuthKeyGroup gives a personal key the group it is held for and moves
// the one-key-per-owner rule to one key per owner and group, the personal key
// counting as an empty group. The new index is built before the old one goes,
// so no moment of the migration admits a second personal key.
func upAddAuthKeyGroup(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		ALTER TABLE auths ADD COLUMN IF NOT EXISTS group_id TEXT NULL;
		ALTER TABLE auths ADD COLUMN IF NOT EXISTS group_name TEXT NULL;
		CREATE UNIQUE INDEX IF NOT EXISTS auths_gateway_owner_group_uniq ON auths (gateway_id, owner_id, COALESCE(group_id, '')) WHERE owner_id IS NOT NULL;
		DROP INDEX IF EXISTS auths_gateway_owner_uniq;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

// downAddAuthKeyGroup deletes every group key, with its links, before it puts
// the one-key-per-owner index back: without the column a group key would be a
// second personal key of its owner, which that index refuses. Personal keys
// are kept.
func downAddAuthKeyGroup(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		DO $$
		BEGIN
			IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'auths'::regclass AND attname = 'group_id' AND NOT attisdropped) THEN
				DELETE FROM consumer_auth WHERE auth_id IN (SELECT id FROM auths WHERE owner_id IS NOT NULL AND group_id IS NOT NULL);
				DELETE FROM auths WHERE owner_id IS NOT NULL AND group_id IS NOT NULL;
			END IF;
		END $$;
		CREATE UNIQUE INDEX IF NOT EXISTS auths_gateway_owner_uniq ON auths (gateway_id, owner_id) WHERE owner_id IS NOT NULL;
		DROP INDEX IF EXISTS auths_gateway_owner_group_uniq;
		ALTER TABLE auths DROP COLUMN IF EXISTS group_name;
		ALTER TABLE auths DROP COLUMN IF EXISTS group_id;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
