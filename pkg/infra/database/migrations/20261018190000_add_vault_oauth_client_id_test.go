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

func TestAddVaultOAuthClientIDMigration(t *testing.T) {
	const column = `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'vault_credentials'::regclass AND attname = 'oauth_client_id' AND NOT attisdropped`
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE vault_credentials (
			id UUID PRIMARY KEY,
			gateway_id UUID NOT NULL,
			principal_sub TEXT NOT NULL,
			provider TEXT NOT NULL,
			account_ref TEXT NOT NULL DEFAULT '',
			access_token TEXT NOT NULL,
			refresh_token TEXT NOT NULL DEFAULT '',
			scopes JSONB,
			expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		) ON COMMIT DROP;
		INSERT INTO vault_credentials (id, gateway_id, principal_sub, provider, access_token, created_at, updated_at)
		VALUES ('bbbbbbbb-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-00000000000c', 'alice', 'linear', 'tok', now(), now())`)

	runTwice(t, ctx, tx, upAddVaultOAuthClientID)
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'vault_credentials'::regclass AND attname = 'oauth_client_id' AND atttypid = 'text'::regtype AND attnotnull`))
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM vault_credentials WHERE oauth_client_id = ''`), "existing grants keep an empty client id")

	runTwice(t, ctx, tx, downAddVaultOAuthClientID)
	require.Zero(t, countOf(t, ctx, tx, column))
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM vault_credentials`), "the down migration keeps every grant")
}
