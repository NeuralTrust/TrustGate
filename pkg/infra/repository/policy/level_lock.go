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
	"hash/fnv"
	"math"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const lockedPolicyColumns = `
		SELECT p.id, p.gateway_id, p.name, p.slug, p.enabled, p.global, p.mcp_scope,
		       COALESCE((SELECT array_agg(cp.consumer_id ORDER BY cp.consumer_id)
		                   FROM consumer_policy cp WHERE cp.policy_id = p.id), '{}')::uuid[] AS consumer_ids`

// WithSlugLocked takes the write lock of one (gateway, slug), reads the
// enabled policies of that pair other than exclude, and runs fn inside the
// same transaction: the context it hands fn carries the transaction, so the
// write fn makes commits with the decision that allowed it or not at all.
//
// The lock is an advisory one and not only the FOR UPDATE of the rows it
// returns, because the writes this guards are mostly inserts: two creates of
// the first two policies of a slug find no row to lock, so row locks alone let
// both through and both take the level (RUN-1621, rule 3.3). The row locks are
// still taken, so a policy cannot be edited out from under a decision that
// read it by a write that does not pass through here. exclude is left out of
// them because the caller is about to rewrite that row itself.
func (r *Repository) WithSlugLocked(
	ctx context.Context,
	gatewayID ids.GatewayID,
	slug string,
	exclude ids.PolicyID,
	fn func(ctx context.Context, occupants []*domain.Policy) error,
) error {
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, slugLockKey(gatewayID, slug)); err != nil {
			return fmt.Errorf("policy repository: lock slug: %w", err)
		}
		occupants, err := lockSameSlugPolicies(ctx, tx, gatewayID, slug, exclude)
		if err != nil {
			return err
		}
		return fn(database.TxContext(ctx, tx), occupants)
	})
}

func lockSameSlugPolicies(
	ctx context.Context,
	tx pgx.Tx,
	gatewayID ids.GatewayID,
	slug string,
	exclude ids.PolicyID,
) ([]*domain.Policy, error) {
	query := lockedPolicyColumns + `
		  FROM policies p
		 WHERE p.gateway_id = $1
		   AND p.slug = $2
		   AND p.id <> $3
		   AND p.enabled
		 ORDER BY p.created_at, p.id
		 FOR UPDATE OF p`
	rows, err := tx.Query(ctx, query, gatewayID.UUID(), slug, exclude.UUID())
	if err != nil {
		return nil, fmt.Errorf("policy repository: lock same slug policies: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Policy, 0)
	for rows.Next() {
		p, err := scanLockedPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("policy repository: scan locked policy: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policy repository: iter locked policies: %w", err)
	}
	return out, nil
}

// scanLockedPolicy reads the columns the occupancy of a policy is computed
// from. The rest are left at their zero value on purpose: this policy is a
// candidate for a conflict, never something the caller hands back.
func scanLockedPolicy(s rowScanner) (*domain.Policy, error) {
	p := &domain.Policy{}
	var scopeRaw []byte
	var consumerIDs []uuid.UUID
	if err := s.Scan(
		&p.ID, &p.GatewayID, &p.Name, &p.Slug, &p.Enabled, &p.Global, &scopeRaw, &consumerIDs,
	); err != nil {
		return nil, err
	}
	scope, err := unmarshalMCPScope(scopeRaw)
	if err != nil {
		return nil, err
	}
	p.MCPScope = scope
	p.ConsumerIDs = ids.FromUUIDs[ids.ConsumerKind](consumerIDs)
	return p, nil
}

func slugLockKey(gatewayID ids.GatewayID, slug string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(gatewayID.String()))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(slug))
	return int64(h.Sum64() & math.MaxInt64)
}
