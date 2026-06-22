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

// enforceJunctionSameGatewayDDL adds a defense-in-depth guard so junction rows
// can only link entities that belong to the same gateway, even if a future bug
// or a caller that bypasses the application layer tries to cross tenants. The
// application layer already validates this; the trigger is the last line.
const enforceJunctionSameGatewayDDL = `
	CREATE OR REPLACE FUNCTION enforce_junction_same_gateway() RETURNS trigger AS $$
	DECLARE
		left_gw  UUID;
		right_gw UUID;
	BEGIN
		IF TG_TABLE_NAME = 'consumer_registry' THEN
			SELECT gateway_id INTO left_gw  FROM consumers  WHERE id = NEW.consumer_id;
			SELECT gateway_id INTO right_gw FROM registries WHERE id = NEW.registry_id;
		ELSIF TG_TABLE_NAME = 'consumer_role' THEN
			SELECT gateway_id INTO left_gw  FROM consumers WHERE id = NEW.consumer_id;
			SELECT gateway_id INTO right_gw FROM roles     WHERE id = NEW.role_id;
		ELSIF TG_TABLE_NAME = 'consumer_auth' THEN
			SELECT gateway_id INTO left_gw  FROM consumers WHERE id = NEW.consumer_id;
			SELECT gateway_id INTO right_gw FROM auths     WHERE id = NEW.auth_id;
		ELSIF TG_TABLE_NAME = 'consumer_policy' THEN
			SELECT gateway_id INTO left_gw  FROM consumers WHERE id = NEW.consumer_id;
			SELECT gateway_id INTO right_gw FROM policies  WHERE id = NEW.policy_id;
		ELSIF TG_TABLE_NAME = 'role_registry' THEN
			SELECT gateway_id INTO left_gw  FROM roles      WHERE id = NEW.role_id;
			SELECT gateway_id INTO right_gw FROM registries WHERE id = NEW.registry_id;
		END IF;
		IF left_gw IS NULL OR right_gw IS NULL OR left_gw <> right_gw THEN
			RAISE EXCEPTION 'cross_gateway_link on %', TG_TABLE_NAME USING ERRCODE = 'AG422';
		END IF;
		RETURN NEW;
	END;
	$$ LANGUAGE plpgsql;

	DROP TRIGGER IF EXISTS consumer_registry_gateway_guard ON consumer_registry;
	CREATE TRIGGER consumer_registry_gateway_guard
		BEFORE INSERT ON consumer_registry
		FOR EACH ROW EXECUTE FUNCTION enforce_junction_same_gateway();

	DROP TRIGGER IF EXISTS consumer_role_gateway_guard ON consumer_role;
	CREATE TRIGGER consumer_role_gateway_guard
		BEFORE INSERT ON consumer_role
		FOR EACH ROW EXECUTE FUNCTION enforce_junction_same_gateway();

	DROP TRIGGER IF EXISTS consumer_auth_gateway_guard ON consumer_auth;
	CREATE TRIGGER consumer_auth_gateway_guard
		BEFORE INSERT ON consumer_auth
		FOR EACH ROW EXECUTE FUNCTION enforce_junction_same_gateway();

	DROP TRIGGER IF EXISTS consumer_policy_gateway_guard ON consumer_policy;
	CREATE TRIGGER consumer_policy_gateway_guard
		BEFORE INSERT ON consumer_policy
		FOR EACH ROW EXECUTE FUNCTION enforce_junction_same_gateway();

	DROP TRIGGER IF EXISTS role_registry_gateway_guard ON role_registry;
	CREATE TRIGGER role_registry_gateway_guard
		BEFORE INSERT ON role_registry
		FOR EACH ROW EXECUTE FUNCTION enforce_junction_same_gateway();`

const dropJunctionSameGatewayDDL = `
	DROP TRIGGER IF EXISTS role_registry_gateway_guard ON role_registry;
	DROP TRIGGER IF EXISTS consumer_policy_gateway_guard ON consumer_policy;
	DROP TRIGGER IF EXISTS consumer_auth_gateway_guard ON consumer_auth;
	DROP TRIGGER IF EXISTS consumer_role_gateway_guard ON consumer_role;
	DROP TRIGGER IF EXISTS consumer_registry_gateway_guard ON consumer_registry;
	DROP FUNCTION IF EXISTS enforce_junction_same_gateway();`

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260622120000_enforce_junction_same_gateway",
		Name: "enforce same-gateway links on junction tables",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, enforceJunctionSameGatewayDDL)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, dropJunctionSameGatewayDDL)
			return err
		},
	})
}
