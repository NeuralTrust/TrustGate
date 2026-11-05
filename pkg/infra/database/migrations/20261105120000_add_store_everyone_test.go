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

func TestAddStoreEveryoneMigration(t *testing.T) {
	const gatewayG = "aaaaaaaa-0000-0000-0000-00000000000e"
	const table = `SELECT COUNT(*) FROM pg_class WHERE relname = 'store_everyone' AND relnamespace = pg_my_temp_schema()`
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE gateways (id UUID PRIMARY KEY) ON COMMIT DROP;
		INSERT INTO gateways (id) VALUES ('`+gatewayG+`')`)

	runTwice(t, ctx, tx, upAddStoreEveryone)
	require.Equal(t, 1, countOf(t, ctx, tx, table))
	const insert = `INSERT INTO store_everyone (gateway_id, mode, grants, excluded_groups, created_at, updated_at) VALUES ($1, $2, '[]', '[]', now(), now())`
	_, err := tx.Exec(ctx, insert, gatewayG, "curated")
	require.NoError(t, err)
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, gatewayG, "open"), "one object per gateway")
	require.Equal(t, "23514", sqlStateOf(t, ctx, tx, `UPDATE store_everyone SET mode = 'none'`), "the mode is open or curated")
	require.Equal(t, "23503", sqlStateOf(t, ctx, tx, insert, "bbbbbbbb-0000-0000-0000-00000000000e", "open"), "the gateway must exist")
	_, err = tx.Exec(ctx, `DELETE FROM gateways`)
	require.NoError(t, err)
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM store_everyone`), "a gateway's object goes with it")

	runTwice(t, ctx, tx, downAddStoreEveryone)
	require.Zero(t, countOf(t, ctx, tx, table))
}
