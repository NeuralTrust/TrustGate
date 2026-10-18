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

func TestAddInstallationNamingVersionMigration(t *testing.T) {
	const gatewayG = "aaaaaaaa-0000-0000-0000-0000000000c2"
	const versionColumn = `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'store_installations'::regclass AND attname = 'naming_version' AND NOT attisdropped`
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE store_installations (
			id UUID PRIMARY KEY,
			gateway_id UUID NOT NULL,
			principal_sub TEXT NOT NULL,
			catalog_code TEXT NOT NULL
		) ON COMMIT DROP;
		INSERT INTO store_installations (id, gateway_id, principal_sub, catalog_code)
		VALUES ('bbbbbbbb-0000-0000-0000-0000000000c2', '`+gatewayG+`', 'ana', 'com.clickup/mcp')`)

	runTwice(t, ctx, tx, upAddInstallationNamingVersion)
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'store_installations'::regclass AND attname = 'naming_version' AND atttypid = 'int2'::regtype AND NOT attnotnull AND NOT atthasdef`))
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM store_installations WHERE naming_version IS NOT NULL`), "existing installs stay on the original names")
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM store_installations WHERE catalog_code = 'com.clickup/mcp'`), "the migration does not rewrite or drop the row")

	runTwice(t, ctx, tx, downAddInstallationNamingVersion)
	require.Zero(t, countOf(t, ctx, tx, versionColumn))
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM store_installations`), "the down migration keeps every install")
}
