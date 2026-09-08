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

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260909150000_backfill_signin_identity_for_credentialless_mcp",
		Name: "identity=platform for MCP consumers that hold no credential of their own",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// The built-in identity provider now only rescues a consumer whose
			// users sign in (see pathScope): an application that authenticates as
			// itself must not become enterable by any platform login when it
			// holds no credential. Consumers created before `identity` existed
			// carry the machine default, so the ones with no auth attached — the
			// only ones the built-in provider serves today — are marked as what
			// they in fact are, keeping their current behaviour. Consumers that
			// already say who they act for are left untouched.
			const backfill = `
				UPDATE consumers c
				SET identity = '{"acts_for_users": true, "source": "platform"}'::jsonb
				WHERE c.type = 'MCP'
				  AND c.identity = '{"acts_for_users": false}'::jsonb
				  AND NOT EXISTS (
					SELECT 1 FROM consumer_auth ca WHERE ca.consumer_id = c.id
				  );`
			_, err := tx.Exec(ctx, backfill)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			// Reverting cannot tell a backfilled row from one an admin set, so it
			// only undoes the exact shape written above for still-credentialless
			// MCP consumers.
			const revert = `
				UPDATE consumers c
				SET identity = '{"acts_for_users": false}'::jsonb
				WHERE c.type = 'MCP'
				  AND c.identity = '{"acts_for_users": true, "source": "platform"}'::jsonb
				  AND NOT EXISTS (
					SELECT 1 FROM consumer_auth ca WHERE ca.consumer_id = c.id
				  );`
			_, err := tx.Exec(ctx, revert)
			return err
		},
	})
}
