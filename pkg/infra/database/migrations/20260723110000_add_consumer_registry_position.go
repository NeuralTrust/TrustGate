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
		ID:   "20260723110000_add_consumer_registry_position",
		Name: "preserve consumer registry insertion order",
		Up:   upConsumerRegistryPosition,
		Down: downConsumerRegistryPosition,
	})
}

func upConsumerRegistryPosition(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		CREATE SEQUENCE IF NOT EXISTS consumer_registry_position_seq;

		ALTER TABLE consumer_registry ADD COLUMN IF NOT EXISTS position BIGINT;

		ALTER SEQUENCE consumer_registry_position_seq OWNED BY consumer_registry.position;
		ALTER TABLE consumer_registry
			ALTER COLUMN position SET DEFAULT nextval('consumer_registry_position_seq');`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downConsumerRegistryPosition(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE consumer_registry DROP COLUMN IF EXISTS position;
		DROP SEQUENCE IF EXISTS consumer_registry_position_seq;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
