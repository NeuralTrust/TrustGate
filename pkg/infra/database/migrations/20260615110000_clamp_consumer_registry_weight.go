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
		ID:   "20260615110000_clamp_consumer_registry_weight",
		Name: "clamp consumer_registry weights to the new 1..100 range",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				UPDATE consumer_registry SET weight = 100 WHERE weight > 100;
				UPDATE consumer_registry SET weight = 1 WHERE weight < 1;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		// Down is a no-op: clamping into 1..100 is lossy, so the pre-migration
		// weights cannot be reconstructed.
		Down: func(ctx context.Context, tx pgx.Tx) error {
			return nil
		},
	})
}
