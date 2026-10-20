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

package sessionrevocation

import (
	"context"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/sessionrevocation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/jackc/pgx/v5"
)

var _ domain.Store = (*Repository)(nil)

// Repository is the pgx adapter for session_revocations. Each upsert commits
// a config-snapshot change marker in the same transaction.
type Repository struct {
	conn   *database.Connection
	outbox outbox.Appender
}

// NewRepository builds the repository from the shared connection.
func NewRepository(conn *database.Connection, appender outbox.Appender) *Repository {
	return &Repository{conn: conn, outbox: appender}
}

// Upsert records revokedAt for the subject. A row that already exists keeps
// the later instant, so a retried or reordered write cannot move the marker
// backwards. The snapshot outbox marker commits with the row.
func (r *Repository) Upsert(ctx context.Context, gatewayID, org, subject string, revokedAt time.Time) error {
	if org == "" || subject == "" || revokedAt.IsZero() {
		return fmt.Errorf("session revocations: org, subject and revoked_at are required")
	}
	id, err := ids.Parse[ids.GatewayKind](gatewayID)
	if err != nil {
		return fmt.Errorf("session revocations: gateway id: %w", err)
	}
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO session_revocations (gateway_id, org, subject, revoked_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (gateway_id, org, subject) DO UPDATE
			SET revoked_at = GREATEST(session_revocations.revoked_at, EXCLUDED.revoked_at)`,
			id.String(), org, subject, revokedAt.UTC()); err != nil {
			return fmt.Errorf("session revocations: upsert: %w", err)
		}
		if r.outbox == nil {
			return fmt.Errorf("session revocations: snapshot outbox is not configured")
		}
		return r.outbox.AppendTx(ctx, tx)
	})
}

// ListActive returns revocations strictly after since.
func (r *Repository) ListActive(ctx context.Context, since time.Time) ([]domain.Record, error) {
	if r.conn == nil || r.conn.Pool == nil {
		return nil, fmt.Errorf("session revocations: nil connection")
	}
	rows, err := r.conn.Pool.Query(ctx, `
		SELECT gateway_id::text, org, subject, revoked_at
		FROM session_revocations
		WHERE revoked_at > $1`, since.UTC())
	if err != nil {
		return nil, fmt.Errorf("session revocations: list: %w", err)
	}
	defer rows.Close()

	var out []domain.Record
	for rows.Next() {
		var rec domain.Record
		if err := rows.Scan(&rec.GatewayID, &rec.Org, &rec.Subject, &rec.RevokedAt); err != nil {
			return nil, fmt.Errorf("session revocations: list: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session revocations: list: %w", err)
	}
	return out, nil
}
