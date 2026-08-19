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
		ID:   "20260814120000_add_consumer_protocol_acceptance",
		Name: "add consumer protocol_acceptance",
		Up:   upAddConsumerProtocolAcceptance,
		Down: downAddConsumerProtocolAcceptance,
	})
}

func upAddConsumerProtocolAcceptance(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE consumers ADD COLUMN IF NOT EXISTS protocol_acceptance TEXT;
		ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_protocol_acceptance_check;
		ALTER TABLE consumers ADD CONSTRAINT consumers_protocol_acceptance_check CHECK (protocol_acceptance IN ('dual_era', 'legacy_only'));`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddConsumerProtocolAcceptance(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_protocol_acceptance_check;
		ALTER TABLE consumers DROP COLUMN IF EXISTS protocol_acceptance;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
