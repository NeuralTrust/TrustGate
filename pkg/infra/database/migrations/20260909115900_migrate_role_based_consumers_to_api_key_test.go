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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The tables as main has them, reduced to the columns the migration reads or
// writes. Consumers:
//
//	a — role_based LLM, two roles over two LLM registries and one MCP registry,
//	    entering through an OIDC provider.
//	b — role_based LLM that already holds an api key, and an oauth2 provider.
//	c — inline, with its own registry and an OIDC provider: not touched.
const roleBasedConsumersSetup = `
	CREATE TEMP TABLE consumers (
		id           UUID PRIMARY KEY,
		gateway_id   UUID NOT NULL,
		name         TEXT NOT NULL,
		type         TEXT NOT NULL DEFAULT 'LLM',
		routing_mode TEXT NOT NULL DEFAULT 'inline',
		updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
	) ON COMMIT DROP;
	CREATE TEMP TABLE registries (id UUID PRIMARY KEY, type TEXT NOT NULL DEFAULT 'LLM') ON COMMIT DROP;
	CREATE TEMP TABLE roles (id UUID PRIMARY KEY) ON COMMIT DROP;
	CREATE TEMP TABLE role_registry (role_id UUID, registry_id UUID, PRIMARY KEY (role_id, registry_id)) ON COMMIT DROP;
	CREATE TEMP TABLE consumer_role (consumer_id UUID, role_id UUID, PRIMARY KEY (consumer_id, role_id)) ON COMMIT DROP;
	CREATE TEMP TABLE consumer_registry (
		consumer_id UUID,
		registry_id UUID,
		weight      INT NOT NULL DEFAULT 1,
		PRIMARY KEY (consumer_id, registry_id)
	) ON COMMIT DROP;
	CREATE TEMP TABLE auths (
		id         UUID PRIMARY KEY,
		gateway_id UUID NOT NULL,
		name       TEXT NOT NULL,
		type       TEXT NOT NULL,
		enabled    BOOLEAN NOT NULL DEFAULT true,
		config     JSONB NOT NULL DEFAULT '{}',
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		key_hash   TEXT,
		key_prefix TEXT,
		key_suffix TEXT
	) ON COMMIT DROP;
	CREATE TEMP TABLE consumer_auth (consumer_id UUID, auth_id UUID, PRIMARY KEY (consumer_id, auth_id)) ON COMMIT DROP;

	INSERT INTO consumers (id, gateway_id, name, routing_mode) VALUES
		('aaaaaaaa-0000-0000-0000-00000000000a', '99999999-0000-0000-0000-000000000009', 'Role app', 'role_based'),
		('bbbbbbbb-0000-0000-0000-00000000000b', '99999999-0000-0000-0000-000000000009', 'Keyed app', 'role_based'),
		('cccccccc-0000-0000-0000-00000000000c', '99999999-0000-0000-0000-000000000009', 'Inline app', 'inline');
	INSERT INTO registries (id, type) VALUES
		('11111111-0000-0000-0000-000000000001', 'LLM'),
		('22222222-0000-0000-0000-000000000002', 'LLM'),
		('33333333-0000-0000-0000-000000000003', 'MCP'),
		('44444444-0000-0000-0000-000000000004', 'LLM');
	INSERT INTO roles (id) VALUES
		('e1111111-0000-0000-0000-000000000001'),
		('e2222222-0000-0000-0000-000000000002'),
		('e3333333-0000-0000-0000-000000000003');
	INSERT INTO role_registry (role_id, registry_id) VALUES
		('e1111111-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001'),
		('e2222222-0000-0000-0000-000000000002', '11111111-0000-0000-0000-000000000001'),
		('e2222222-0000-0000-0000-000000000002', '22222222-0000-0000-0000-000000000002'),
		('e2222222-0000-0000-0000-000000000002', '33333333-0000-0000-0000-000000000003'),
		('e3333333-0000-0000-0000-000000000003', '44444444-0000-0000-0000-000000000004');
	INSERT INTO consumer_role (consumer_id, role_id) VALUES
		('aaaaaaaa-0000-0000-0000-00000000000a', 'e1111111-0000-0000-0000-000000000001'),
		('aaaaaaaa-0000-0000-0000-00000000000a', 'e2222222-0000-0000-0000-000000000002'),
		('bbbbbbbb-0000-0000-0000-00000000000b', 'e3333333-0000-0000-0000-000000000003');
	INSERT INTO consumer_registry (consumer_id, registry_id) VALUES
		('cccccccc-0000-0000-0000-00000000000c', '44444444-0000-0000-0000-000000000004');
	INSERT INTO auths (id, gateway_id, name, type, created_at, updated_at, key_hash) VALUES
		('a0000000-0000-0000-0000-0000000000a1', '99999999-0000-0000-0000-000000000009', 'Okta', 'oidc', now(), now(), NULL),
		('a0000000-0000-0000-0000-0000000000a2', '99999999-0000-0000-0000-000000000009', 'Entra', 'oauth2', now(), now(), NULL),
		('a0000000-0000-0000-0000-0000000000a3', '99999999-0000-0000-0000-000000000009', 'existing key', 'api_key', now(), now(), 'deadbeef');
	INSERT INTO consumer_auth (consumer_id, auth_id) VALUES
		('aaaaaaaa-0000-0000-0000-00000000000a', 'a0000000-0000-0000-0000-0000000000a1'),
		('bbbbbbbb-0000-0000-0000-00000000000b', 'a0000000-0000-0000-0000-0000000000a2'),
		('bbbbbbbb-0000-0000-0000-00000000000b', 'a0000000-0000-0000-0000-0000000000a3'),
		('cccccccc-0000-0000-0000-00000000000c', 'a0000000-0000-0000-0000-0000000000a1')`

func TestMigrateRoleBasedConsumersToAPIKey(t *testing.T) {
	ctx, tx := beginShadowTx(t, roleBasedConsumersSetup)

	// Twice: the second run finds no role_based consumer and adds nothing.
	runTwice(t, ctx, tx, upMigrateRoleBasedConsumersToAPIKey)

	require.Zero(t, countOf(t, ctx, tx, `SELECT count(*) FROM consumers WHERE routing_mode = 'role_based'`))
	require.Zero(t, countOf(t, ctx, tx, `SELECT count(*) FROM consumer_role`), "every role link is gone")

	registriesOf := func(consumerID string) []string {
		rows, err := tx.Query(ctx, `SELECT registry_id::text FROM consumer_registry WHERE consumer_id = $1 ORDER BY 1`, consumerID)
		require.NoError(t, err)
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id string
			require.NoError(t, rows.Scan(&id))
			out = append(out, id)
		}
		require.NoError(t, rows.Err())
		return out
	}
	// a routes over what its roles reached, once each, and not the MCP server.
	require.Equal(t, []string{"11111111-0000-0000-0000-000000000001", "22222222-0000-0000-0000-000000000002"}, registriesOf("aaaaaaaa-0000-0000-0000-00000000000a"))
	require.Equal(t, []string{"44444444-0000-0000-0000-000000000004"}, registriesOf("bbbbbbbb-0000-0000-0000-00000000000b"))

	// a: the OIDC link is gone, the auth stays (c still uses it), and one
	// migrated api key is linked, stored like any other: a hash and a preview.
	require.Zero(t, countOf(t, ctx, tx, `
		SELECT count(*) FROM consumer_auth
		 WHERE consumer_id = 'aaaaaaaa-0000-0000-0000-00000000000a' AND auth_id = 'a0000000-0000-0000-0000-0000000000a1'`))
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT count(*) FROM auths WHERE id = 'a0000000-0000-0000-0000-0000000000a1'`))
	var name, hash, prefix, suffix, gateway string
	require.NoError(t, tx.QueryRow(ctx, `
		SELECT a.name, a.key_hash, a.key_prefix, a.key_suffix, a.gateway_id::text
		  FROM consumer_auth ca JOIN auths a ON a.id = ca.auth_id
		 WHERE ca.consumer_id = 'aaaaaaaa-0000-0000-0000-00000000000a' AND a.type = 'api_key' AND a.enabled`).
		Scan(&name, &hash, &prefix, &suffix, &gateway))
	require.Equal(t, "Role app (migrated)", name)
	require.Len(t, hash, 64)
	require.True(t, strings.HasPrefix(prefix, "ag_"), "prefix %q", prefix)
	require.NotEmpty(t, suffix)
	require.Equal(t, "99999999-0000-0000-0000-000000000009", gateway)

	// b already had a key: it keeps it, gains no second one, and loses the
	// identity provider.
	require.Equal(t, 1, countOf(t, ctx, tx, `
		SELECT count(*) FROM consumer_auth ca JOIN auths a ON a.id = ca.auth_id
		 WHERE ca.consumer_id = 'bbbbbbbb-0000-0000-0000-00000000000b'`))
	require.Equal(t, 1, countOf(t, ctx, tx, `
		SELECT count(*) FROM consumer_auth
		 WHERE consumer_id = 'bbbbbbbb-0000-0000-0000-00000000000b' AND auth_id = 'a0000000-0000-0000-0000-0000000000a3'`))

	// c was inline: its registry and its identity provider are as they were.
	require.Equal(t, []string{"44444444-0000-0000-0000-000000000004"}, registriesOf("cccccccc-0000-0000-0000-00000000000c"))
	require.Equal(t, 1, countOf(t, ctx, tx, `
		SELECT count(*) FROM consumer_auth
		 WHERE consumer_id = 'cccccccc-0000-0000-0000-00000000000c' AND auth_id = 'a0000000-0000-0000-0000-0000000000a1'`))

	// One key was minted in all, for a.
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT count(*) FROM auths WHERE name LIKE '% (migrated)'`))
}

// A database that already dropped role-based routing (or never had it) has
// nothing to convert.
func TestMigrateRoleBasedConsumersToAPIKey_NoRoles(t *testing.T) {
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE consumers (id UUID PRIMARY KEY, gateway_id UUID, name TEXT, type TEXT) ON COMMIT DROP`)
	runTwice(t, ctx, tx, upMigrateRoleBasedConsumersToAPIKey)
}
