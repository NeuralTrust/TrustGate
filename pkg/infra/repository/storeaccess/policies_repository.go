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

package storeaccess

import (
	"context"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/jackc/pgx/v5"
)

const selectPolicyColumns = `
	SELECT gateway_id, principal_type, principal_id, mode, created_at, updated_at
	  FROM store_access_policies`

var _ domain.PolicyRepository = (*PolicyRepository)(nil)

// PolicyRepository is the pgx-backed per-principal Store access policy store.
// Policies ride the config snapshot, so writes append a change marker.
type PolicyRepository struct {
	conn   *database.Connection
	outbox outbox.Appender
}

func NewPolicyRepository(conn *database.Connection, appender outbox.Appender) *PolicyRepository {
	return &PolicyRepository{conn: conn, outbox: appender}
}

func (r *PolicyRepository) withMarkedTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if r.outbox == nil {
			return nil
		}
		return r.outbox.AppendTx(ctx, tx)
	})
}

func (r *PolicyRepository) UpsertPolicy(ctx context.Context, p *domain.Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	created := p.CreatedAt
	if created.IsZero() {
		created = now
	}
	const query = `
		INSERT INTO store_access_policies
			(gateway_id, principal_type, principal_id, mode, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (gateway_id, principal_type, principal_id) DO UPDATE
			SET mode       = EXCLUDED.mode,
			    updated_at = EXCLUDED.updated_at`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, p.GatewayID, string(p.PrincipalType), p.PrincipalID, p.Mode, created, now); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *PolicyRepository) DeletePolicy(ctx context.Context, gatewayID ids.GatewayID, principalType domain.PrincipalType, principalID string) error {
	const query = `
		DELETE FROM store_access_policies
		 WHERE gateway_id = $1 AND principal_type = $2 AND principal_id = $3`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, gatewayID, string(principalType), principalID); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *PolicyRepository) ListPoliciesByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Policy, error) {
	const query = selectPolicyColumns + `
		WHERE gateway_id = $1
		ORDER BY principal_type, principal_id`
	return r.queryPolicies(ctx, query, gatewayID)
}

func (r *PolicyRepository) ListPolicies(ctx context.Context, page, size int) ([]*domain.Policy, int, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 100
	}
	var total int
	if err := r.conn.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM store_access_policies`).Scan(&total); err != nil {
		return nil, 0, mapPgError(err)
	}
	const query = selectPolicyColumns + `
		ORDER BY gateway_id, principal_type, principal_id
		LIMIT $1 OFFSET $2`
	items, err := r.queryPolicies(ctx, query, size, (page-1)*size)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *PolicyRepository) queryPolicies(ctx context.Context, query string, args ...any) ([]*domain.Policy, error) {
	rows, err := r.conn.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()
	out := make([]*domain.Policy, 0)
	for rows.Next() {
		var (
			p             domain.Policy
			principalType string
		)
		if err := rows.Scan(&p.GatewayID, &principalType, &p.PrincipalID, &p.Mode, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store access policy repository: scan: %w", err)
		}
		p.PrincipalType = domain.PrincipalType(principalType)
		out = append(out, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, mapPgError(err)
	}
	return out, nil
}
