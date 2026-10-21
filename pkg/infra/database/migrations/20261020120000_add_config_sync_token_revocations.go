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
		ID:   "20261020120000_add_config_sync_token_revocations",
		Name: "record config-sync token revocations per gateway scope",
		Up:   upAddConfigSyncTokenRevocations,
		Down: downAddConfigSyncTokenRevocations,
	})
}

func upAddConfigSyncTokenRevocations(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		CREATE TABLE IF NOT EXISTS config_sync_token_revocations (
			scope      TEXT NOT NULL,
			jti        TEXT NOT NULL,
			revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (scope, jti)
		);
		CREATE TABLE IF NOT EXISTS config_sync_scope_issued_before (
			scope         TEXT PRIMARY KEY,
			issued_before BIGINT NOT NULL,
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
		);`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddConfigSyncTokenRevocations(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		DROP TABLE IF EXISTS config_sync_scope_issued_before;
		DROP TABLE IF EXISTS config_sync_token_revocations;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
