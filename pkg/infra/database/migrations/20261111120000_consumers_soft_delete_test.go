//go:build functional

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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConsumersSoftDeleteMigration(t *testing.T) {
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE consumers (
			id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			gateway_id UUID NOT NULL,
			name       TEXT NOT NULL,
			slug       TEXT NOT NULL,
			CONSTRAINT consumers_gateway_name_unique UNIQUE (gateway_id, name)
		) ON COMMIT DROP;
		CREATE UNIQUE INDEX consumers_slug_unique_idx ON consumers (slug);
		INSERT INTO consumers (gateway_id, name, slug) VALUES ('00000000-0000-0000-0000-000000000001', 'app', 'app')`)

	const insert = `INSERT INTO consumers (gateway_id, name, slug) VALUES ('00000000-0000-0000-0000-000000000001', $1, $2)`
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, "app", "other"))
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, "other", "app"))

	runTwice(t, ctx, tx, upConsumersSoftDelete)
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, "app", "other"), "two live consumers cannot share a name")
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, "other", "app"), "two live consumers cannot share a slug")

	_, err := tx.Exec(ctx, `UPDATE consumers SET deleted_at = NOW() WHERE slug = 'app'`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, insert, "app", "app")
	require.NoError(t, err, "a deleted consumer frees its name and slug")
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM pg_indexes WHERE indexname = 'consumers_gateway_live_idx' AND schemaname LIKE 'pg_temp%'`))

	runTwice(t, ctx, tx, downConsumersSoftDelete)
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumers`), "down drops the deleted consumers")
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'consumers'::regclass AND attname = 'deleted_at' AND NOT attisdropped`))
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, "app", "other"))
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, "other", "app"))
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM pg_constraint WHERE conname = 'consumers_gateway_name_unique' AND conrelid = 'consumers'::regclass`))

	runTwice(t, ctx, tx, upConsumersSoftDelete)
}
