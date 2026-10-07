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
		ID:   "20261006100200_add_consumer_auth_grant",
		Name: "give personal consumer_auth links a grant level, priority and grant time",
		Up:   upAddConsumerAuthGrant,
		Down: downAddConsumerAuthGrant,
	})
}

// The grant time is bounded to the unix epoch through year 9999 UTC, the range
// every plane can round-trip through JSON and time.Time.
func upAddConsumerAuthGrant(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		ALTER TABLE consumer_auth ADD COLUMN IF NOT EXISTS level TEXT NULL;
		ALTER TABLE consumer_auth ADD COLUMN IF NOT EXISTS priority INTEGER NULL;
		ALTER TABLE consumer_auth ADD COLUMN IF NOT EXISTS granted_at TIMESTAMPTZ NULL;
		ALTER TABLE consumer_auth DROP CONSTRAINT IF EXISTS consumer_auth_grant_check;
		ALTER TABLE consumer_auth ADD CONSTRAINT consumer_auth_grant_check CHECK (
			num_nonnulls(level, priority, granted_at) = 0
			OR (num_nonnulls(level, priority, granted_at) = 3 AND level IN ('user', 'group', 'all') AND priority >= 0
				AND granted_at >= TIMESTAMPTZ '1970-01-01 00:00:00+00'
				AND granted_at <= TIMESTAMPTZ '9999-12-31 23:59:59.999999+00'));`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddConsumerAuthGrant(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE consumer_auth DROP CONSTRAINT IF EXISTS consumer_auth_grant_check;
		ALTER TABLE consumer_auth DROP COLUMN IF EXISTS granted_at;
		ALTER TABLE consumer_auth DROP COLUMN IF EXISTS priority;
		ALTER TABLE consumer_auth DROP COLUMN IF EXISTS level;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
