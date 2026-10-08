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

func TestAddAuthOwnerEmailMigration(t *testing.T) {
	const gatewayG = "aaaaaaaa-0000-0000-0000-00000000000b"
	const emailColumn = `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'auths'::regclass AND attname = 'owner_email' AND NOT attisdropped`
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE auths (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), gateway_id UUID NOT NULL, owner_id TEXT NULL) ON COMMIT DROP;
		INSERT INTO auths (gateway_id) VALUES ('`+gatewayG+`');
		INSERT INTO auths (gateway_id, owner_id) VALUES ('`+gatewayG+`', 'alice')`)

	runTwice(t, ctx, tx, upAddAuthOwnerEmail)
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'auths'::regclass AND attname = 'owner_email' AND atttypid = 'text'::regtype AND NOT attnotnull`))
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM auths WHERE owner_email IS NOT NULL`), "existing keys carry no email")

	runTwice(t, ctx, tx, downAddAuthOwnerEmail)
	require.Zero(t, countOf(t, ctx, tx, emailColumn))
	require.Equal(t, 2, countOf(t, ctx, tx, `SELECT COUNT(*) FROM auths`), "the down migration keeps every key")
}
