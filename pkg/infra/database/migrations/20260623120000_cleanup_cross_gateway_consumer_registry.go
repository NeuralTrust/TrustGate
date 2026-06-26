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

const cleanupCrossGatewayConsumerRegistryDDL = `
	DELETE FROM consumer_registry cr
	USING consumers c, registries r
	WHERE cr.consumer_id = c.id
	  AND cr.registry_id = r.id
	  AND c.gateway_id <> r.gateway_id;`

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260623120000_cleanup_cross_gateway_consumer_registry",
		Name: "delete cross-gateway consumer_registry rows",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, cleanupCrossGatewayConsumerRegistryDDL)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			return nil
		},
	})
}
