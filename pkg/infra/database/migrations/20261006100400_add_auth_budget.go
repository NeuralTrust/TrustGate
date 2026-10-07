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
		ID:   "20261006100400_add_auth_budget",
		Name: "give a personal api key an optional spending limit",
		Up:   upAddAuthBudget,
		Down: downAddAuthBudget,
	})
}

func upAddAuthBudget(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `ALTER TABLE auths ADD COLUMN IF NOT EXISTS budget JSONB NULL;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddAuthBudget(ctx context.Context, tx pgx.Tx) error {
	const ddl = `ALTER TABLE auths DROP COLUMN IF EXISTS budget;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
