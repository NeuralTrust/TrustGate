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

package policy

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/jackc/pgx/v5"
)

// PruneRegistryReferencesTx removes registryID from the mcp_scope of every
// policy in the gateway using the caller's transaction, so the prune and the
// registry delete that triggers it commit or roll back together. A scope left
// without destinations is written back as '{}', never NULL, so the policy goes
// dormant instead of widening to the whole consumer. It appends no
// config-snapshot marker: the delete that owns the transaction does.
func (r *Repository) PruneRegistryReferencesTx(
	ctx context.Context,
	tx pgx.Tx,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) (registrydomain.PruneReport, error) {
	policies, err := lockScopedPolicies(ctx, tx, gatewayID, registryID)
	if err != nil {
		return registrydomain.PruneReport{}, err
	}
	var report registrydomain.PruneReport
	for _, p := range policies {
		if !p.PruneRegistry(registryID) {
			continue
		}
		if err := updateMCPScope(ctx, tx, p); err != nil {
			return registrydomain.PruneReport{}, err
		}
		report.Policies = append(report.Policies, registrydomain.PolicyPrune{
			PolicyID: p.ID,
			Emptied:  p.MCPScope.IsEmpty(),
		})
	}
	return report, nil
}

func lockScopedPolicies(
	ctx context.Context,
	tx pgx.Tx,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) ([]*domain.Policy, error) {
	query := `
		SELECT id, mcp_scope
		  FROM policies
		 WHERE gateway_id = $1
		   AND mcp_scope IS NOT NULL
		   AND ` + fmt.Sprintf(mcpScopeReferencesRegistry, 2) + `
		 FOR UPDATE`
	rows, err := tx.Query(ctx, query, gatewayID, registryID.String())
	if err != nil {
		return nil, fmt.Errorf("policy repository: lock scoped policies: %w", err)
	}
	defer rows.Close()

	policies := make([]*domain.Policy, 0)
	for rows.Next() {
		p := &domain.Policy{GatewayID: gatewayID}
		var scopeRaw []byte
		if err := rows.Scan(&p.ID, &scopeRaw); err != nil {
			return nil, fmt.Errorf("policy repository: scan scoped policy: %w", err)
		}
		scope, err := unmarshalMCPScope(scopeRaw)
		if err != nil {
			return nil, fmt.Errorf("policy repository: %w", err)
		}
		p.MCPScope = scope
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policy repository: iter scoped policies: %w", err)
	}
	return policies, nil
}

func updateMCPScope(ctx context.Context, tx pgx.Tx, p *domain.Policy) error {
	scopeBytes, err := marshalMCPScope(p.MCPScope)
	if err != nil {
		return fmt.Errorf("policy repository: marshal mcp_scope: %w", err)
	}
	const query = `UPDATE policies SET mcp_scope = $2, updated_at = now() WHERE id = $1`
	if _, err := tx.Exec(ctx, query, p.ID, scopeBytes); err != nil {
		return mapPgError(err)
	}
	return nil
}
