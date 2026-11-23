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

// Deleting a gateway soft-deletes its consumers, so the consumers row must be
// able to outlive the gateway row: the gateway_id foreign key is dropped.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20261123120000_consumers_survive_gateway_delete",
		Name: "drop consumers.gateway_id foreign key so soft-deleted consumers outlive their gateway",
		Up:   upConsumersSurviveGatewayDelete,
		Down: downConsumersSurviveGatewayDelete,
	})
}

func upConsumersSurviveGatewayDelete(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, consumersLockTimeout+`
		ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_gateway_id_fkey;`)
	return err
}

// Down drops the consumers left behind by deleted gateways before restoring the
// foreign key, which they would otherwise violate.
func downConsumersSurviveGatewayDelete(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, consumersLockTimeout+`
		DELETE FROM consumers WHERE gateway_id NOT IN (SELECT id FROM gateways);
		ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_gateway_id_fkey;
		ALTER TABLE consumers ADD CONSTRAINT consumers_gateway_id_fkey
			FOREIGN KEY (gateway_id) REFERENCES gateways(id) ON DELETE RESTRICT;`)
	return err
}
