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

// Package outbox provides the pgx-backed adapter for the config-snapshot
// change-marker outbox: an in-transaction appender the admin repositories share,
// plus the drain/prune reads the dispatcher runs.
package outbox

import (
	"context"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Appender inserts a change marker inside a caller-owned transaction so the marker
// commits atomically with the config write that triggered it. The admin
// repositories depend on this narrow interface.
type Appender interface {
	AppendTx(ctx context.Context, tx pgx.Tx) error
}

// poolQuerier is the subset of pgxpool.Pool the drain/prune reads need, kept small to fake in tests.
type poolQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Repository is the pgx adapter over config_snapshot_outbox. It implements the
// infra Appender and the app-side OutboxRepository (drain/prune) contracts.
type Repository struct {
	pool poolQuerier
}

// NewRepository builds the outbox repository from the shared connection.
func NewRepository(conn *database.Connection) *Repository {
	return &Repository{pool: conn.Pool}
}

// AppendTx inserts one change marker inside tx.
func (r *Repository) AppendTx(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `INSERT INTO config_snapshot_outbox DEFAULT VALUES`); err != nil {
		return fmt.Errorf("outbox: append change marker: %w", err)
	}
	return nil
}

// Pending returns the seqs of every marker currently visible, oldest first. The
// dispatcher captures this set before compiling so it later drains exactly the
// markers whose writes are guaranteed to be in the compiled snapshot; a marker that
// becomes visible afterwards (a lower seq committing after a higher one) is absent
// from the set and survives to the next cycle.
func (r *Repository) Pending(ctx context.Context) ([]int64, error) {
	rows, err := r.pool.Query(ctx, `SELECT seq FROM config_snapshot_outbox ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("outbox: pending: %w", err)
	}
	defer rows.Close()
	var seqs []int64
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			return nil, fmt.Errorf("outbox: scan pending seq: %w", err)
		}
		seqs = append(seqs, seq)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("outbox: iterate pending: %w", err)
	}
	return seqs, nil
}

// PendingCount returns the number of markers currently in the outbox.
func (r *Repository) PendingCount(ctx context.Context) (int64, error) {
	var count int64
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM config_snapshot_outbox`).Scan(&count); err != nil {
		return 0, fmt.Errorf("outbox: pending count: %w", err)
	}
	return count, nil
}

// DeleteSeqs removes exactly the given marker seqs, returning the number deleted. It
// is a no-op for an empty set.
func (r *Repository) DeleteSeqs(ctx context.Context, seqs []int64) (int64, error) {
	if len(seqs) == 0 {
		return 0, nil
	}
	tag, err := r.pool.Exec(ctx, `DELETE FROM config_snapshot_outbox WHERE seq = ANY($1)`, seqs)
	if err != nil {
		return 0, fmt.Errorf("outbox: delete seqs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PruneOlderThan enforces the safety bound so a stuck dispatcher can never grow the
// table unbounded: it deletes markers created before cutoff and, when keepMax > 0,
// any marker beyond the newest keepMax rows. It returns the number deleted.
func (r *Repository) PruneOlderThan(ctx context.Context, cutoff time.Time, keepMax int) (int64, error) {
	if keepMax < 0 {
		keepMax = 0
	}
	const prune = `
		DELETE FROM config_snapshot_outbox
		WHERE created_at < $1
		   OR seq <= COALESCE(
			(SELECT seq FROM config_snapshot_outbox ORDER BY seq DESC OFFSET $2 LIMIT 1),
			0
		   )`
	tag, err := r.pool.Exec(ctx, prune, cutoff, keepMax)
	if err != nil {
		return 0, fmt.Errorf("outbox: prune older than %s: %w", cutoff, err)
	}
	return tag.RowsAffected(), nil
}
