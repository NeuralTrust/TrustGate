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
		ID:   "20260805120000_add_list_filter_indexes",
		Name: "add composite indexes for gateway-scoped list filtering and sorting",
		Up:   upAddListFilterIndexes,
		Down: downAddListFilterIndexes,
	})
}

func upAddListFilterIndexes(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		CREATE INDEX IF NOT EXISTS roles_gateway_created_at_id_idx
			ON roles (gateway_id, created_at DESC, id);
		CREATE INDEX IF NOT EXISTS auths_gateway_created_at_id_idx
			ON auths (gateway_id, created_at DESC, id);
		CREATE INDEX IF NOT EXISTS auths_gateway_type_idx
			ON auths (gateway_id, type);
		CREATE INDEX IF NOT EXISTS auths_gateway_enabled_idx
			ON auths (gateway_id, enabled);
		CREATE INDEX IF NOT EXISTS consumers_gateway_created_at_id_idx
			ON consumers (gateway_id, created_at DESC, id);
		CREATE INDEX IF NOT EXISTS consumers_gateway_type_idx
			ON consumers (gateway_id, type);
		CREATE INDEX IF NOT EXISTS consumers_gateway_active_idx
			ON consumers (gateway_id, active);
		CREATE INDEX IF NOT EXISTS policies_gateway_created_at_id_idx
			ON policies (gateway_id, created_at DESC, id);
		CREATE INDEX IF NOT EXISTS policies_gateway_priority_idx
			ON policies (gateway_id, priority);`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddListFilterIndexes(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		DROP INDEX IF EXISTS policies_gateway_priority_idx;
		DROP INDEX IF EXISTS policies_gateway_created_at_id_idx;
		DROP INDEX IF EXISTS consumers_gateway_active_idx;
		DROP INDEX IF EXISTS consumers_gateway_type_idx;
		DROP INDEX IF EXISTS consumers_gateway_created_at_id_idx;
		DROP INDEX IF EXISTS auths_gateway_enabled_idx;
		DROP INDEX IF EXISTS auths_gateway_type_idx;
		DROP INDEX IF EXISTS auths_gateway_created_at_id_idx;
		DROP INDEX IF EXISTS roles_gateway_created_at_id_idx;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
