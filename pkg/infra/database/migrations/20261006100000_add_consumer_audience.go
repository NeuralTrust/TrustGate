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
		ID:   "20261006100000_add_consumer_audience",
		Name: "give consumers an application or personal audience",
		Up:   upAddConsumerAudience,
		Down: downAddConsumerAudience,
	})
}

// llmStoreLockTimeout bounds how long an LLM Store migration waits for a table
// lock. Without it an ALTER queued behind a long read would in turn queue
// every later read and write on the table; failing fast lets the rollout retry.
const llmStoreLockTimeout = `SET LOCAL lock_timeout = '5s';`

func upAddConsumerAudience(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		ALTER TABLE consumers ADD COLUMN IF NOT EXISTS audience TEXT NOT NULL DEFAULT 'application';
		ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_audience_check;
		ALTER TABLE consumers ADD CONSTRAINT consumers_audience_check CHECK (audience IN ('application', 'personal'));`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddConsumerAudience(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		DO $$
		BEGIN
			IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'consumers'::regclass AND attname = 'audience' AND NOT attisdropped) THEN
				UPDATE consumers SET active = false WHERE audience = 'personal';
			END IF;
		END $$;
		ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_audience_check;
		ALTER TABLE consumers DROP COLUMN IF EXISTS audience;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
