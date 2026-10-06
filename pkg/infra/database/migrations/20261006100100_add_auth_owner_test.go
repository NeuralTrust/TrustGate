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

func TestAddAuthOwnerMigration(t *testing.T) {
	const gatewayG, gatewayH = "aaaaaaaa-0000-0000-0000-00000000000a", "bbbbbbbb-0000-0000-0000-00000000000b"
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE auths (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), gateway_id UUID NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE) ON COMMIT DROP;
		INSERT INTO auths (gateway_id) VALUES ('`+gatewayG+`'), ('`+gatewayG+`')`)

	runTwice(t, ctx, tx, upAddAuthOwner)
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM auths WHERE owner_id IS NOT NULL`))
	const insert = `INSERT INTO auths (gateway_id, owner_id) VALUES ($1, $2)`
	_, err := tx.Exec(ctx, insert, gatewayG, "alice")
	require.NoError(t, err)
	require.Equal(t, "23505", sqlStateOf(t, ctx, tx, insert, gatewayG, "alice"))
	require.Empty(t, sqlStateOf(t, ctx, tx, insert, gatewayH, "alice"))
	require.Empty(t, sqlStateOf(t, ctx, tx, insert, gatewayG, nil))
	_, err = tx.Exec(ctx, insert, gatewayH, "alice")
	require.NoError(t, err)

	runTwice(t, ctx, tx, downAddAuthOwner)
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'auths'::regclass AND attname = 'owner_id' AND NOT attisdropped`))
	require.Equal(t, 2, countOf(t, ctx, tx, `SELECT COUNT(*) FROM auths WHERE NOT enabled`))
	require.Equal(t, 2, countOf(t, ctx, tx, `SELECT COUNT(*) FROM auths WHERE enabled`))
}
