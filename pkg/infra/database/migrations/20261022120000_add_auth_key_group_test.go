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

func TestAddAuthKeyGroupMigration(t *testing.T) {
	const gatewayG, gatewayH = "aaaaaaaa-0000-0000-0000-00000000000c", "bbbbbbbb-0000-0000-0000-00000000000c"
	const ownerIndex = `SELECT COUNT(*) FROM pg_class WHERE relname = 'auths_gateway_owner_uniq' AND relnamespace = pg_my_temp_schema()`
	const groupColumns = `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'auths'::regclass AND attname IN ('group_id', 'group_name') AND atttypid = 'text'::regtype AND NOT attnotnull AND NOT attisdropped`
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE auths (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), gateway_id UUID NOT NULL, owner_id TEXT NULL) ON COMMIT DROP;
		CREATE TEMP TABLE consumer_auth (consumer_id UUID NOT NULL DEFAULT gen_random_uuid(), auth_id UUID NOT NULL REFERENCES auths (id)) ON COMMIT DROP;
		CREATE UNIQUE INDEX auths_gateway_owner_uniq ON auths (gateway_id, owner_id) WHERE owner_id IS NOT NULL;
		INSERT INTO auths (gateway_id) VALUES ('`+gatewayG+`'), ('`+gatewayG+`');
		INSERT INTO auths (gateway_id, owner_id) VALUES ('`+gatewayG+`', 'alice')`)

	runTwice(t, ctx, tx, upAddAuthKeyGroup)
	require.Equal(t, 2, countOf(t, ctx, tx, groupColumns))
	require.Zero(t, countOf(t, ctx, tx, ownerIndex))
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM auths WHERE group_id IS NOT NULL`), "existing keys are personal keys")

	const insert = `INSERT INTO auths (gateway_id, owner_id, group_id, group_name) VALUES ($1, $2, $3, $4)`
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, gatewayG, "alice", nil, nil), "a second personal key")
	_, err := tx.Exec(ctx, insert, gatewayG, "alice", "g-eng", "engineering")
	require.NoError(t, err, "a key for a group beside the personal key")
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, gatewayG, "alice", "g-eng", "engineering (renamed)"), "a second key for the same group")
	require.Empty(t, sqlStateOf(t, ctx, tx, insert, gatewayG, "alice", "g-sre", "sre"))
	require.Empty(t, sqlStateOf(t, ctx, tx, insert, gatewayG, "bob", "g-eng", "engineering"))
	require.Empty(t, sqlStateOf(t, ctx, tx, insert, gatewayH, "alice", "g-eng", "engineering"))
	require.Empty(t, sqlStateOf(t, ctx, tx, insert, gatewayG, nil, nil, nil), "application keys stay unbounded")
	_, err = tx.Exec(ctx, `INSERT INTO consumer_auth (auth_id) SELECT id FROM auths WHERE owner_id IS NOT NULL`)
	require.NoError(t, err)

	runTwice(t, ctx, tx, downAddAuthKeyGroup)
	require.Zero(t, countOf(t, ctx, tx, groupColumns))
	require.Equal(t, 1, countOf(t, ctx, tx, ownerIndex))
	require.Equal(t, 3, countOf(t, ctx, tx, `SELECT COUNT(*) FROM auths`), "the group key goes, every other key stays")
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumer_auth`), "and so do its links")
}
