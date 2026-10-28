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

func TestAddKeyGroupBudgetsMigration(t *testing.T) {
	const gatewayG = "aaaaaaaa-0000-0000-0000-00000000000d"
	const table = `SELECT COUNT(*) FROM pg_class WHERE relname = 'key_group_budgets' AND relnamespace = pg_my_temp_schema()`
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE gateways (id UUID PRIMARY KEY) ON COMMIT DROP;
		INSERT INTO gateways (id) VALUES ('`+gatewayG+`')`)

	runTwice(t, ctx, tx, upAddKeyGroupBudgets)
	require.Equal(t, 1, countOf(t, ctx, tx, table))
	const insert = `INSERT INTO key_group_budgets (gateway_id, group_id, monthly_limit_usd, action, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now())`
	_, err := tx.Exec(ctx, insert, gatewayG, "g-eng", 100.5, "block")
	require.NoError(t, err)
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, gatewayG, "g-eng", 1, "alert"), "one budget per gateway and group")
	require.Equal(t, "23514", sqlStateOf(t, ctx, tx, insert, gatewayG, "g-sre", 1, "throttle"), "the action is alert or block")
	require.Equal(t, "23503", sqlStateOf(t, ctx, tx, insert, "bbbbbbbb-0000-0000-0000-00000000000d", "g-eng", 1, "block"), "the gateway must exist")
	_, err = tx.Exec(ctx, `DELETE FROM gateways`)
	require.NoError(t, err)
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM key_group_budgets`), "a gateway's budgets go with it")

	runTwice(t, ctx, tx, downAddKeyGroupBudgets)
	require.Zero(t, countOf(t, ctx, tx, table))
}
