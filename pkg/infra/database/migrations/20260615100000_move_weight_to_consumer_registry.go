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
		ID:   "20260615100000_move_weight_to_consumer_registry",
		Name: "move registry weight to the consumer_registry association",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumer_registry ADD COLUMN IF NOT EXISTS weight INT NOT NULL DEFAULT 1;
				UPDATE consumer_registry cr
					SET weight = GREATEST(r.weight, 1)
					FROM registries r
					WHERE cr.registry_id = r.id;
				ALTER TABLE registries DROP COLUMN IF EXISTS weight;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		// Down is best-effort: the per-consumer weights are collapsed back into a
		// single per-registry value (the max across associations) and registries
		// that are no longer associated with any consumer fall back to 0. The
		// original pre-migration weights cannot be fully reconstructed.
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE registries ADD COLUMN IF NOT EXISTS weight INT NOT NULL DEFAULT 0;
				UPDATE registries r
					SET weight = sub.weight
					FROM (
						SELECT registry_id, MAX(weight) AS weight
						FROM consumer_registry
						GROUP BY registry_id
					) sub
					WHERE r.id = sub.registry_id;
				ALTER TABLE consumer_registry DROP COLUMN IF EXISTS weight;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
