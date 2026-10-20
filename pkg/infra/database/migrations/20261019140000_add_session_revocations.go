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
		ID:   "20261019140000_add_session_revocations",
		Name: "record default-IdP session revocations for data planes",
		Up:   upAddSessionRevocations,
		Down: downAddSessionRevocations,
	})
}

func upAddSessionRevocations(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		CREATE TABLE IF NOT EXISTS session_revocations (
			gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
			org        TEXT NOT NULL,
			subject    TEXT NOT NULL,
			revoked_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (gateway_id, org, subject)
		);
		CREATE INDEX IF NOT EXISTS session_revocations_revoked_at_idx
			ON session_revocations (revoked_at);`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddSessionRevocations(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		DROP TABLE IF EXISTS session_revocations;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
