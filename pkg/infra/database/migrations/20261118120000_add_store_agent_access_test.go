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

func TestAddStoreAgentAccessMigration(t *testing.T) {
	const gatewayG = "aaaaaaaa-0000-0000-0000-00000000000f"
	const table = `SELECT COUNT(*) FROM pg_class WHERE relname = 'store_agent_access' AND relnamespace = pg_my_temp_schema()`
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE gateways (id UUID PRIMARY KEY) ON COMMIT DROP;
		INSERT INTO gateways (id) VALUES ('`+gatewayG+`')`)

	runTwice(t, ctx, tx, upAddStoreAgentAccess)
	require.Equal(t, 1, countOf(t, ctx, tx, table))
	const insert = `INSERT INTO store_agent_access (gateway_id, principal_type, principal_id, mode, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now())`
	_, err := tx.Exec(ctx, insert, gatewayG, "all", "", "all")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, insert, gatewayG, "group", "eng", "selected")
	require.NoError(t, err)
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, gatewayG, "group", "eng", "none"), "one row per principal")
	require.Equal(t, "23514", sqlStateOf(t, ctx, tx, insert, gatewayG, "team", "x", "all"), "the principal type is all, group or user")
	require.Equal(t, "23514", sqlStateOf(t, ctx, tx, insert, gatewayG, "user", "ana", "open"), "the mode is all, selected or none")
	require.Equal(t, "23503", sqlStateOf(t, ctx, tx, insert, "bbbbbbbb-0000-0000-0000-00000000000f", "all", "", "all"), "the gateway must exist")
	_, err = tx.Exec(ctx, `DELETE FROM gateways`)
	require.NoError(t, err)
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM store_agent_access`), "a gateway's rows go with it")

	runTwice(t, ctx, tx, downAddStoreAgentAccess)
	require.Zero(t, countOf(t, ctx, tx, table))
}
