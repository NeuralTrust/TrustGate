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

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

// The scope only knows groups now, so the unmarshal would drop users and
// except_users on its own. Leaving the rows as they are is what makes that
// dangerous: a scope whose only principal was users keeps its destination and
// starts applying to every caller of it, which is a silent widening no one
// asked for. A scope left without any group after the strip is therefore
// written as '{}' — dormant, the state a registry delete already leaves behind
// (Policy.PruneRegistry) — so the policy stops running instead, and has to be
// rewritten in terms of groups by hand. A scope that still names groups or
// except_groups keeps them and only loses its user entries, which narrows it
// to the audience the product decision keeps.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260917120000_drop_policy_mcp_scope_users",
		Name: "drop users and except_users from policies.mcp_scope (groups are the only principal)",
		Up:   upDropPolicyMCPScopeUsers,
		Down: downDropPolicyMCPScopeUsers,
	})
}

const dropPolicyMCPScopeUsersDDL = `
	UPDATE policies
	SET mcp_scope = CASE
		WHEN jsonb_array_length(
			COALESCE(NULLIF(mcp_scope -> 'groups', 'null'::jsonb), '[]'::jsonb)
		) > 0
		  OR jsonb_array_length(
			COALESCE(NULLIF(mcp_scope -> 'except_groups', 'null'::jsonb), '[]'::jsonb)
		) > 0
		THEN mcp_scope - 'users' - 'except_users'
		ELSE '{}'::jsonb
	END
	WHERE mcp_scope IS NOT NULL
	  AND jsonb_typeof(mcp_scope) = 'object'
	  AND (jsonb_exists(mcp_scope, 'users') OR jsonb_exists(mcp_scope, 'except_users'));`

func upDropPolicyMCPScopeUsers(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, dropPolicyMCPScopeUsersDDL)
	return err
}

func downDropPolicyMCPScopeUsers(_ context.Context, _ pgx.Tx) error {
	// The user entries are gone from the JSON and a scope reset to '{}' no
	// longer says what it named, so there is nothing to restore. The column
	// itself is untouched by this migration.
	return nil
}
