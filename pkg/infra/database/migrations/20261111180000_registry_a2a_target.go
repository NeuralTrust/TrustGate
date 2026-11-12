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
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20261111180000_registry_a2a_target",
		Name: "add registry type A2A and a2a_target",
		Up:   upRegistryA2ATarget,
		Down: downRegistryA2ATarget,
	})
}

func upRegistryA2ATarget(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `
		ALTER TABLE registries ADD COLUMN IF NOT EXISTS a2a_target JSONB;
		ALTER TABLE registries DROP CONSTRAINT IF EXISTS registries_type_check;
		ALTER TABLE registries ADD CONSTRAINT registries_type_check CHECK (type IN ('LLM', 'MCP', 'A2A'));`)
	return err
}

func downRegistryA2ATarget(ctx context.Context, tx pgx.Tx) error {
	var agents bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM registries WHERE type = 'A2A')`).Scan(&agents); err != nil {
		return err
	}
	if agents {
		return errors.New("registries of type A2A exist; delete them before rolling back")
	}
	_, err := tx.Exec(ctx, `
		ALTER TABLE registries DROP CONSTRAINT IF EXISTS registries_type_check;
		ALTER TABLE registries ADD CONSTRAINT registries_type_check CHECK (type IN ('LLM', 'MCP'));
		ALTER TABLE registries DROP COLUMN IF EXISTS a2a_target;`)
	return err
}
