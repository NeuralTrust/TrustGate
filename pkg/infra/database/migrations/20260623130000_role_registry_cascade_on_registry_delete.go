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

const roleRegistryCascadeUpDDL = `
	ALTER TABLE role_registry DROP CONSTRAINT IF EXISTS role_registry_registry_id_fkey;
	ALTER TABLE role_registry ADD CONSTRAINT role_registry_registry_id_fkey
		FOREIGN KEY (registry_id) REFERENCES registries(id) ON DELETE CASCADE;`

const roleRegistryCascadeDownDDL = `
	ALTER TABLE role_registry DROP CONSTRAINT IF EXISTS role_registry_registry_id_fkey;
	ALTER TABLE role_registry ADD CONSTRAINT role_registry_registry_id_fkey
		FOREIGN KEY (registry_id) REFERENCES registries(id) ON DELETE RESTRICT;`

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260623130000_role_registry_cascade_on_registry_delete",
		Name: "cascade role_registry rows when a registry is deleted",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, roleRegistryCascadeUpDDL)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, roleRegistryCascadeDownDDL)
			return err
		},
	})
}
