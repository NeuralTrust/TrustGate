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
		ID:   "20261008150000_preserve_legacy_smart_routing",
		Name: "preserve legacy ladders under session routing",
		Up:   upPreserveLegacySmartRouting,
		Down: downPreserveLegacySmartRouting,
	})
}

func upPreserveLegacySmartRouting(ctx context.Context, tx pgx.Tx) error {
	return upSmartRoutingMigration(ctx, tx, "sr1_legacy_routing_migration_backup")
}

func downPreserveLegacySmartRouting(ctx context.Context, tx pgx.Tx) error {
	return downSmartRoutingMigration(ctx, tx, "sr1_legacy_routing_migration_backup")
}
