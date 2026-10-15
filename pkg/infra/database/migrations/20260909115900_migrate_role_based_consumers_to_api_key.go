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
	"encoding/json"
	"fmt"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

// The next migration (20260909120000_drop_roles_and_routing_mode) drops roles
// and every consumer's routing_mode. A role_based consumer could not hold a
// registry of its own (the routing-mode guard refused it), so it would come out
// of that drop routing to nothing: every call it serves would fail.
//
// The few that exist are test consumers, so they are turned into what a
// consumer is now, before the roles go:
//
//   - It routes inline over the registries its roles routed to, all of them.
//     The per-role split is gone with the roles; the union is what it could
//     reach before, minus the claim that picked between them.
//   - It enters with an api key. The identity provider its roles read claims
//     from is unlinked (the auth itself stays, it may serve other consumers),
//     and one api key named "<consumer> (migrated)" is linked unless it already
//     holds one. Its secret is random and never shown, because a migration has
//     nobody to show it to: an admin rotates the key, from Applications → Auth
//     or POST /v1/gateways/{gateway_id}/auths/{id}/rotate, and gets a secret
//     that works.
//
// A database that never had roles, or that already dropped them, has nothing
// to convert, and the migration does nothing there.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260909115900_migrate_role_based_consumers_to_api_key",
		Name: "turn role_based consumers into inline consumers behind an api key, before roles are dropped",
		Up:   upMigrateRoleBasedConsumersToAPIKey,
		Down: downMigrateRoleBasedConsumersToAPIKey,
	})
}

const roleBasedSchemaPresent = `
	SELECT to_regclass('consumer_role') IS NOT NULL
	   AND to_regclass('role_registry') IS NOT NULL
	   AND EXISTS (
	         SELECT 1 FROM pg_attribute
	          WHERE attrelid = to_regclass('consumers')
	            AND attname = 'routing_mode'
	            AND NOT attisdropped
	       )`

type roleBasedConsumer struct {
	id        string
	gatewayID string
	name      string
}

func upMigrateRoleBasedConsumersToAPIKey(ctx context.Context, tx pgx.Tx) error {
	var present bool
	if err := tx.QueryRow(ctx, roleBasedSchemaPresent).Scan(&present); err != nil {
		return fmt.Errorf("look for role-based routing: %w", err)
	}
	if !present {
		return nil
	}

	rows, err := tx.Query(ctx, `SELECT id::text, gateway_id::text, name FROM consumers WHERE routing_mode = 'role_based' ORDER BY id`)
	if err != nil {
		return fmt.Errorf("list role-based consumers: %w", err)
	}
	consumers, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (roleBasedConsumer, error) {
		var c roleBasedConsumer
		return c, row.Scan(&c.id, &c.gatewayID, &c.name)
	})
	if err != nil {
		return fmt.Errorf("list role-based consumers: %w", err)
	}

	for _, c := range consumers {
		if err := convertRoleBasedConsumer(ctx, tx, c); err != nil {
			return fmt.Errorf("consumer %s: %w", c.id, err)
		}
	}
	return nil
}

func convertRoleBasedConsumer(ctx context.Context, tx pgx.Tx, c roleBasedConsumer) error {
	// What its roles routed to, read before the roles are unlinked. A registry
	// of another plane is left out: an LLM consumer cannot route to an MCP
	// server, and the gateway would refuse to load it.
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT rr.registry_id::text
		  FROM consumer_role cr
		  JOIN role_registry rr ON rr.role_id = cr.role_id
		  JOIN registries r ON r.id = rr.registry_id
		  JOIN consumers c ON c.id = cr.consumer_id
		 WHERE cr.consumer_id = $1
		   AND upper(r.type) = upper(c.type)
		 ORDER BY 1`, c.id)
	if err != nil {
		return fmt.Errorf("read its roles' registries: %w", err)
	}
	registryIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("read its roles' registries: %w", err)
	}

	// Roles first: the routing-mode guard refuses inline while roles are linked,
	// and a registry while the consumer is role_based.
	if _, err := tx.Exec(ctx, `DELETE FROM consumer_role WHERE consumer_id = $1`, c.id); err != nil {
		return fmt.Errorf("unlink its roles: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE consumers SET routing_mode = 'inline', updated_at = now() WHERE id = $1`, c.id); err != nil {
		return fmt.Errorf("switch it to inline routing: %w", err)
	}
	for _, registryID := range registryIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO consumer_registry (consumer_id, registry_id) VALUES ($1, $2)
			ON CONFLICT DO NOTHING`, c.id, registryID); err != nil {
			return fmt.Errorf("link registry %s: %w", registryID, err)
		}
	}

	// The identity provider served the claims the roles mapped; with the roles
	// gone it is unlinked from this consumer. Only the link goes: the auth may
	// be linked elsewhere.
	if _, err := tx.Exec(ctx, `
		DELETE FROM consumer_auth ca
		 USING auths a
		 WHERE ca.consumer_id = $1
		   AND a.id = ca.auth_id
		   AND a.type <> 'api_key'`, c.id); err != nil {
		return fmt.Errorf("unlink its identity provider: %w", err)
	}

	var hasKey bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM consumer_auth ca JOIN auths a ON a.id = ca.auth_id
			 WHERE ca.consumer_id = $1 AND a.type = 'api_key'
		)`, c.id).Scan(&hasKey); err != nil {
		return fmt.Errorf("look for an api key: %w", err)
	}
	if hasKey {
		return nil
	}
	return linkMigratedAPIKey(ctx, tx, c)
}

// linkMigratedAPIKey creates the consumer's api key and links it. The raw key
// is dropped on the floor: only its hash is stored, as for any key, and nobody
// will ever present it. Rotating the key is how it gets a usable secret.
func linkMigratedAPIKey(ctx context.Context, tx pgx.Tx, c roleBasedConsumer) error {
	gatewayID, err := ids.Parse[ids.GatewayKind](c.gatewayID)
	if err != nil {
		return fmt.Errorf("gateway id: %w", err)
	}
	key, err := authdomain.NewAPIKeyAuth(gatewayID, c.name+" (migrated)", true, nil)
	if err != nil {
		return fmt.Errorf("mint api key: %w", err)
	}
	config, err := json.Marshal(key.Config)
	if err != nil {
		return fmt.Errorf("encode api key config: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auths (id, gateway_id, name, type, enabled, config, created_at, updated_at, key_hash, key_prefix, key_suffix)
		VALUES ($1, $2, $3, 'api_key', true, $4, $5, $5, $6, $7, $8)`,
		key.ID.String(), c.gatewayID, key.Name, config, key.CreatedAt, key.KeyHash, key.KeyPrefix, key.KeySuffix); err != nil {
		return fmt.Errorf("store api key: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO consumer_auth (consumer_id, auth_id) VALUES ($1, $2)`, c.id, key.ID.String()); err != nil {
		return fmt.Errorf("link api key: %w", err)
	}
	return nil
}

// downMigrateRoleBasedConsumersToAPIKey is a no-op: the roles a consumer was
// unlinked from, and the identity provider it entered through, are not
// recorded anywhere a rollback could read them back from. The registries and
// the api key it gained stay, so it keeps routing on the release before.
func downMigrateRoleBasedConsumersToAPIKey(_ context.Context, _ pgx.Tx) error {
	return nil
}
