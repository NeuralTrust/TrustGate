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
		ID:   "20260729110000_drop_auths_gateway_name_unique",
		Name: "allow duplicate auth names per gateway; credentials resolve by id/key_hash",
		Up:   upDropAuthsGatewayNameUnique,
		Down: downDropAuthsGatewayNameUnique,
	})
}

func upDropAuthsGatewayNameUnique(ctx context.Context, tx pgx.Tx) error {
	const ddl = `ALTER TABLE auths DROP CONSTRAINT IF EXISTS auths_gateway_name_unique;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downDropAuthsGatewayNameUnique(ctx context.Context, tx pgx.Tx) error {
	const ddl = `ALTER TABLE auths ADD CONSTRAINT auths_gateway_name_unique UNIQUE (gateway_id, name);`
	_, err := tx.Exec(ctx, ddl)
	return err
}
