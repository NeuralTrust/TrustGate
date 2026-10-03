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
		ID:   "20261003150000_replace_consumer_labels_with_label_sets",
		Name: "replace the consumer traffic labels with traffic label sets",
		Up:   upReplaceConsumerLabelsWithLabelSets,
		Down: downReplaceConsumerLabelsWithLabelSets,
	})
}

// The single labels of the first version are dropped, not converted: the app
// projects the label sets again.
func upReplaceConsumerLabelsWithLabelSets(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE consumers DROP COLUMN IF EXISTS labels;
		ALTER TABLE consumers ADD COLUMN IF NOT EXISTS label_sets JSONB NULL;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downReplaceConsumerLabelsWithLabelSets(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE consumers DROP COLUMN IF EXISTS label_sets;
		ALTER TABLE consumers ADD COLUMN IF NOT EXISTS labels JSONB NULL;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
