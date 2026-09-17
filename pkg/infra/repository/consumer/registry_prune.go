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

package consumer

import (
	"context"
	"encoding/json"
	"fmt"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/jackc/pgx/v5"
)

// PruneRegistryReferences removes registryID from the routing configuration of
// every consumer in the gateway, in its own transaction, and reports what it
// changed.
func (r *Repository) PruneRegistryReferences(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) (registrydomain.PruneReport, error) {
	var report registrydomain.PruneReport
	if err := r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		var err error
		report, err = r.PruneRegistryReferencesTx(ctx, tx, gatewayID, registryID)
		return err
	}); err != nil {
		return registrydomain.PruneReport{}, err
	}
	return report, nil
}

// PruneRegistryReferencesTx removes registryID from the routing configuration of
// every consumer in the gateway using the caller's transaction, so the prune and
// the registry delete that triggers it commit or roll back together. It reports
// the consumers it rewrote and which of their structures it had to null, so the
// caller can record the harm once the transaction commits.
func (r *Repository) PruneRegistryReferencesTx(
	ctx context.Context,
	tx pgx.Tx,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) (registrydomain.PruneReport, error) {
	consumers, err := lockGatewayRoutingReferences(ctx, tx, gatewayID)
	if err != nil {
		return registrydomain.PruneReport{}, err
	}
	var report registrydomain.PruneReport
	for _, consumer := range consumers {
		prune, changed := consumer.PruneRegistry(registryID)
		if !changed {
			continue
		}
		if err := updateConsumerRoutingReferences(ctx, tx, consumer); err != nil {
			return registrydomain.PruneReport{}, err
		}
		report.Consumers = append(report.Consumers, prune)
	}
	return report, nil
}

func lockGatewayRoutingReferences(
	ctx context.Context,
	tx pgx.Tx,
	gatewayID ids.GatewayID,
) ([]*domain.Consumer, error) {
	// RUN-1501: no ORDER BY. Postgres does not guarantee lock acquisition order
	// from one (a seq-scan-plus-sort plan locks in heap order), so it would only
	// read as if it did. Determinism is not needed here either: every other site
	// locks exactly one consumer row, and both this prune and the consumer update
	// take consumers before registries, so no lock inversion exists to order
	// around.
	const query = `
		SELECT id, gateway_id, fallback, model_policies, lb_config, toolkit
		  FROM consumers
		 WHERE gateway_id = $1
		 FOR UPDATE`
	rows, err := tx.Query(ctx, query, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("consumer repository: lock gateway routing references: %w", err)
	}
	defer rows.Close()

	consumers := make([]*domain.Consumer, 0)
	for rows.Next() {
		consumer := &domain.Consumer{}
		var fallbackRaw, modelPoliciesRaw, lbConfigRaw, toolkitRaw []byte
		if err := rows.Scan(
			&consumer.ID,
			&consumer.GatewayID,
			&fallbackRaw,
			&modelPoliciesRaw,
			&lbConfigRaw,
			&toolkitRaw,
		); err != nil {
			return nil, fmt.Errorf("consumer repository: scan routing references: %w", err)
		}
		if err := hydrateConsumerRoutingReferences(consumer, fallbackRaw, modelPoliciesRaw, lbConfigRaw); err != nil {
			return nil, err
		}
		if err := hydrateConsumerToolkit(consumer, toolkitRaw); err != nil {
			return nil, err
		}
		consumers = append(consumers, consumer)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("consumer repository: iter routing references: %w", err)
	}
	return consumers, nil
}

func updateConsumerRoutingReferences(ctx context.Context, tx pgx.Tx, consumer *domain.Consumer) error {
	lbConfigBytes, err := marshalLBConfig(consumer.LBConfig)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal lb_config: %w", err)
	}
	fallbackBytes, err := marshalFallback(consumer.Fallback)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal fallback: %w", err)
	}
	modelPoliciesBytes, err := marshalModelPolicies(consumer.ModelPolicies)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal model_policies: %w", err)
	}
	toolkitBytes, err := marshalToolkit(consumer.Toolkit())
	if err != nil {
		return fmt.Errorf("consumer repository: marshal toolkit: %w", err)
	}
	const query = `
		UPDATE consumers
		   SET lb_config = $2, fallback = $3, model_policies = $4, toolkit = $5, updated_at = NOW()
		 WHERE id = $1`
	if _, err := tx.Exec(ctx, query, consumer.ID, lbConfigBytes, fallbackBytes, modelPoliciesBytes, toolkitBytes); err != nil {
		return mapPgError(err)
	}
	return nil
}

func hydrateConsumerToolkit(consumer *domain.Consumer, toolkitRaw []byte) error {
	if len(toolkitRaw) == 0 {
		return nil
	}
	var toolkit domain.Toolkit
	if err := json.Unmarshal(toolkitRaw, &toolkit); err != nil {
		return fmt.Errorf("scan toolkit: %w", err)
	}
	if len(toolkit) == 0 {
		return nil
	}
	consumer.MCP = &domain.MCPPolicy{Toolkit: toolkit}
	return nil
}
