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
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const dropPolicyMCPScopeUsersSetup = `
	CREATE TEMP TABLE policies (
		id        UUID PRIMARY KEY,
		mcp_scope JSONB
	) ON COMMIT DROP;
	SET LOCAL search_path TO pg_temp;

	INSERT INTO policies (id, mcp_scope) VALUES
		-- Principal selected only by users: dropping the dimension would leave
		-- the registry applying to every caller, so the scope goes dormant.
		('11111111-1111-1111-1111-111111111111',
			'{"registry_ids": ["aaaaaaaa-0000-0000-0000-00000000000a"], "users": ["alice@acme.io"]}'),
		-- Groups survive, users go: the audience narrows, it never widens.
		('22222222-2222-2222-2222-222222222222',
			'{"registry_ids": ["aaaaaaaa-0000-0000-0000-00000000000a"], "groups": ["Finance"], "users": ["alice@acme.io"]}'),
		-- An exception carved out by user has no group left to hang on.
		('33333333-3333-3333-3333-333333333333',
			'{"tools": [{"registry_id": "aaaaaaaa-0000-0000-0000-00000000000a", "tool": "run_query"}], "except_users": ["bob@acme.io"]}'),
		-- except_groups is a principal of its own and keeps the scope alive.
		('44444444-4444-4444-4444-444444444444',
			'{"tools": [{"registry_id": "aaaaaaaa-0000-0000-0000-00000000000a", "tool": "run_query"}], "except_groups": ["Finance"], "except_users": ["bob@acme.io"]}'),
		-- An empty users array still names the retired dimension.
		('55555555-5555-5555-5555-555555555555',
			'{"groups": ["Finance"], "users": []}'),
		-- Never named a user: must come out byte for byte unchanged.
		('66666666-6666-6666-6666-666666666666',
			'{"registry_ids": ["aaaaaaaa-0000-0000-0000-00000000000a"], "groups": ["Finance"]}'),
		-- Already dormant, and consumer-wide: both must stay as they are.
		('77777777-7777-7777-7777-777777777777', '{}'),
		('88888888-8888-8888-8888-888888888888', NULL);`

func TestDropPolicyMCPScopeUsersMigration(t *testing.T) {
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, dropPolicyMCPScopeUsersSetup); err != nil {
		t.Fatalf("setup: %v", err)
	}
	untouchedBefore := mcpScopeJSON(t, ctx, tx, "66666666-6666-6666-6666-666666666666")

	if err := upDropPolicyMCPScopeUsers(ctx, tx); err != nil {
		t.Fatalf("up: %v", err)
	}

	for _, tc := range []struct {
		id   string
		want string
	}{
		{"11111111-1111-1111-1111-111111111111", `{}`},
		{"22222222-2222-2222-2222-222222222222", `{"registry_ids": ["aaaaaaaa-0000-0000-0000-00000000000a"], "groups": ["Finance"]}`},
		{"33333333-3333-3333-3333-333333333333", `{}`},
		{"44444444-4444-4444-4444-444444444444", `{"tools": [{"registry_id": "aaaaaaaa-0000-0000-0000-00000000000a", "tool": "run_query"}], "except_groups": ["Finance"]}`},
		{"55555555-5555-5555-5555-555555555555", `{"groups": ["Finance"]}`},
		{"77777777-7777-7777-7777-777777777777", `{}`},
	} {
		assertScopeEquals(t, ctx, tx, tc.id, tc.want)
	}
	if got := mcpScopeJSON(t, ctx, tx, "88888888-8888-8888-8888-888888888888"); got != "" {
		t.Fatalf("a consumer-wide policy gained a scope: %s", got)
	}
	if after := mcpScopeJSON(t, ctx, tx, "66666666-6666-6666-6666-666666666666"); after != untouchedBefore {
		t.Fatalf("a scope with no user entry was rewritten:\n before %s\n after  %s", untouchedBefore, after)
	}

	settled := allMCPScopeJSON(t, ctx, tx)
	if err := upDropPolicyMCPScopeUsers(ctx, tx); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	for id, want := range settled {
		if got := mcpScopeJSON(t, ctx, tx, id); got != want {
			t.Fatalf("%s changed on replay:\n first  %s\n second %s", id, want, got)
		}
	}
}

func assertScopeEquals(t *testing.T, ctx context.Context, tx pgx.Tx, id, want string) {
	t.Helper()
	var equal bool
	if err := tx.QueryRow(ctx,
		`SELECT mcp_scope = $2::jsonb FROM policies WHERE id = $1`, id, want,
	).Scan(&equal); err != nil {
		t.Fatalf("compare mcp_scope for %s: %v", id, err)
	}
	if !equal {
		t.Fatalf("%s mcp_scope = %s, want %s", id, mcpScopeJSON(t, ctx, tx, id), want)
	}
}

func mcpScopeJSON(t *testing.T, ctx context.Context, tx pgx.Tx, id string) string {
	t.Helper()
	var out *string
	if err := tx.QueryRow(ctx,
		`SELECT mcp_scope::text FROM policies WHERE id = $1`, id,
	).Scan(&out); err != nil {
		t.Fatalf("read mcp_scope for %s: %v", id, err)
	}
	if out == nil {
		return ""
	}
	return *out
}

func allMCPScopeJSON(t *testing.T, ctx context.Context, tx pgx.Tx) map[string]string {
	t.Helper()
	rows, err := tx.Query(ctx, `SELECT id::text, COALESCE(mcp_scope::text, '') FROM policies`)
	if err != nil {
		t.Fatalf("read every mcp_scope: %v", err)
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var id, scope string
		if err := rows.Scan(&id, &scope); err != nil {
			t.Fatalf("scan mcp_scope: %v", err)
		}
		out[id] = scope
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iter mcp_scope: %v", err)
	}
	return out
}
