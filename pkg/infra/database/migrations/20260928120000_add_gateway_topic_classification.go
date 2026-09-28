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
		ID:   "20260928120000_add_gateway_topic_classification",
		Name: "store the per-gateway topic classification config",
		Up:   upAddGatewayTopicClassification,
		Down: downAddGatewayTopicClassification,
	})
}

func upAddGatewayTopicClassification(ctx context.Context, tx pgx.Tx) error {
	const ddl = `ALTER TABLE gateways ADD COLUMN IF NOT EXISTS topic_classification JSONB NULL;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddGatewayTopicClassification(ctx context.Context, tx pgx.Tx) error {
	const ddl = `ALTER TABLE gateways DROP COLUMN IF EXISTS topic_classification;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
