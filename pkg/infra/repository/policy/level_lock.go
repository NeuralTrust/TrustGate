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
		SELECT p.id, p.gateway_id, p.name, p.slug, p.enabled, p.global, p.mcp_wide, p.mcp_scope,
		       COALESCE((SELECT array_agg(cp.consumer_id ORDER BY cp.consumer_id)
		                   FROM consumer_policy cp WHERE cp.policy_id = p.id), '{}')::uuid[] AS consumer_ids`

// WithSlugLocked takes the write lock of one (gateway, slug), reads the
// enabled policies of that pair other than exclude, and runs fn inside the
// same transaction: the context it hands fn carries the transaction, so the
// write fn makes commits with the decision that allowed it or not at all.
//
// The lock is an advisory one and not only row locks, because the writes this
// guards are mostly inserts: two creates of the first two policies of a slug
// find no row to lock, so row locks alone let both through and both take the
// level (RUN-1621, rule 3.3).
//
// The row locks follow one order (RUN-1746): the consumers in linking in
// ascending id FOR KEY SHARE, then the enabled policies of the pair and exclude
// in ascending id FOR UPDATE. A registry delete and a gateway delete lock the
// gateway's consumers and then its policies in that same order, so none of them
// can hold a row another is waiting for, which Postgres would abort with 40P01.
// fn locks no consumer or policy row the transaction does not already hold:
// linking a consumer locks it and exclude, and the only policy row fn writes
// is exclude, matched by id because an update that changes the slug still
// stores the old one. Disabled siblings stay unlocked, since a row fn never
// touches cannot close a cycle.
//
// The occupants are read after the locks, without one. Every occupant that
// existed when they were taken is held, so a write that skips the guard cannot
// change it under the decision. A row committed after that came from such a
// write and occupies no level, and locking it would take it out of id order.
func (r *Repository) WithSlugLocked(
	ctx context.Context,
	gatewayID ids.GatewayID,
	slug string,
	exclude ids.PolicyID,
	linking []ids.ConsumerID,
	fn func(ctx context.Context, occupants []*domain.Policy) error,
) error {
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, slugLockKey(gatewayID, slug)); err != nil {
			return fmt.Errorf("policy repository: lock slug: %w", err)
		}
		if err := lockLinkedConsumers(ctx, tx, linking); err != nil {
			return err
		}
		if err := lockSlugPolicies(ctx, tx, gatewayID, slug, exclude); err != nil {
			return err
		}
		occupants, err := sameSlugOccupants(ctx, tx, gatewayID, slug, exclude)
		if err != nil {
			return err
		}
		return fn(database.TxContext(ctx, tx), occupants)
	})
}

func lockLinkedConsumers(ctx context.Context, tx pgx.Tx, linking []ids.ConsumerID) error {
	if len(linking) == 0 {
		return nil
	}
	const query = `SELECT 1 FROM consumers WHERE id = ANY($1) ORDER BY id FOR KEY SHARE`
	if _, err := tx.Exec(ctx, query, ids.ToUUIDs(linking)); err != nil {
		return fmt.Errorf("policy repository: lock linked consumers: %w", err)
	}
	return nil
}

func lockSlugPolicies(
	ctx context.Context,
	tx pgx.Tx,
	gatewayID ids.GatewayID,
	slug string,
	exclude ids.PolicyID,
) error {
	const query = `
		SELECT 1
		  FROM policies
		 WHERE gateway_id = $1
		   AND ((slug = $2 AND enabled) OR id = $3)
		 ORDER BY id
		 FOR UPDATE`
	if _, err := tx.Exec(ctx, query, gatewayID.UUID(), slug, exclude.UUID()); err != nil {
		return fmt.Errorf("policy repository: lock same slug policies: %w", err)
	}
	return nil
}

func sameSlugOccupants(
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
		 ORDER BY p.created_at, p.id`
	rows, err := tx.Query(ctx, query, gatewayID.UUID(), slug, exclude.UUID())
	if err != nil {
		return nil, fmt.Errorf("policy repository: read same slug policies: %w", err)
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
		&p.ID, &p.GatewayID, &p.Name, &p.Slug, &p.Enabled, &p.Global, &p.MCPWide, &scopeRaw, &consumerIDs,
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
