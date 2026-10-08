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

package registry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/jackc/pgx/v5"
)

func pruneSmartRouting(ctx context.Context, tx pgx.Tx, gatewayID ids.GatewayID, registryID ids.RegistryID) error {
	const query = `
		SELECT id, lb_config, model_policies, fallback,
		       ARRAY(SELECT registry_id FROM consumer_registry WHERE consumer_id = consumers.id)
		  FROM consumers
		 WHERE gateway_id = $1 AND (lb_config->>'algorithm' = 'smart-routing' OR lb_config ? 'smart_routing')
		 ORDER BY id FOR UPDATE`
	rows, err := tx.Query(ctx, query, gatewayID)
	if err != nil {
		return fmt.Errorf("registry repository: lock smart routing: %w", err)
	}
	var consumers []*consumer.Consumer
	for rows.Next() {
		c := &consumer.Consumer{GatewayID: gatewayID}
		var lb, policies, fallback []byte
		var references []ids.RegistryID
		if err := rows.Scan(&c.ID, &lb, &policies, &fallback, &references); err != nil {
			rows.Close()
			return fmt.Errorf("registry repository: scan smart routing: %w", err)
		}
		for _, value := range []struct {
			raw    []byte
			target any
		}{{lb, &c.LBConfig}, {policies, &c.ModelPolicies}, {fallback, &c.Fallback}} {
			if len(value.raw) > 0 {
				if err := json.Unmarshal(value.raw, value.target); err != nil {
					rows.Close()
					return fmt.Errorf("registry repository: decode smart routing: %w", err)
				}
			}
		}
		for _, id := range references {
			if id != registryID {
				c.RegistryIDs = append(c.RegistryIDs, id)
			}
		}
		consumers = append(consumers, c)
	}
	iterationErr := rows.Err()
	rows.Close()
	if iterationErr != nil {
		return fmt.Errorf("registry repository: iterate smart routing: %w", iterationErr)
	}
	for _, c := range consumers {
		if _, changed := c.PruneRegistry(registryID); !changed {
			continue
		}
		if err := c.LBConfig.Validate(c.ModelPolicies); err != nil {
			return fmt.Errorf("registry repository: invalid pruned smart routing: %w", err)
		}
		lb, err := json.Marshal(c.LBConfig)
		if err != nil {
			return err
		}
		policies, err := json.Marshal(c.ModelPolicies)
		if err != nil {
			return err
		}
		fallback, err := json.Marshal(c.Fallback)
		if err != nil {
			return err
		}
		const update = `UPDATE consumers SET lb_config = NULLIF($1::jsonb, 'null'::jsonb),
			model_policies = NULLIF($2::jsonb, 'null'::jsonb), fallback = NULLIF($3::jsonb, 'null'::jsonb),
			updated_at = NOW() WHERE id = $4 AND gateway_id = $5`
		if _, err := tx.Exec(ctx, update, lb, policies, fallback, c.ID, gatewayID); err != nil {
			return fmt.Errorf("registry repository: persist pruned smart routing: %w", err)
		}
	}
	return nil
}
