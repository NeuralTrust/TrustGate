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

// Package configsnapshotlkg provides the pgx-backed store of the admin's
// persisted last-good config snapshots.
package configsnapshotlkg

import (
	"context"
	"fmt"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type poolQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Repository implements appsnapshot.LKGStore over config_snapshot_lkg.
type Repository struct {
	pool poolQuerier
}

var _ appsnapshot.LKGStore = (*Repository)(nil)

// NewRepository builds the repository from the shared connection.
func NewRepository(conn *database.Connection) *Repository {
	return &Repository{pool: conn.Pool}
}

// Save upserts rec only when it is newer than the stored row by compiled_at.
func (r *Repository) Save(ctx context.Context, rec appsnapshot.LKGRecord) (bool, error) {
	const upsert = `
		INSERT INTO config_snapshot_lkg (scope, version, compiled_at, key_id, payload)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (scope) DO UPDATE
		SET version = EXCLUDED.version,
		    compiled_at = EXCLUDED.compiled_at,
		    key_id = EXCLUDED.key_id,
		    payload = EXCLUDED.payload
		WHERE config_snapshot_lkg.compiled_at < EXCLUDED.compiled_at`
	tag, err := r.pool.Exec(ctx, upsert, rec.Scope, rec.Version, rec.CompiledAt, rec.KeyID, rec.Payload)
	if err != nil {
		return false, fmt.Errorf("configsnapshotlkg: save scope %q: %w", rec.Scope, err)
	}
	return tag.RowsAffected() > 0, nil
}

// Touch advances compiled_at of the rows that still hold the given versions.
func (r *Repository) Touch(ctx context.Context, held []appsnapshot.LKGVersion, compiledAt time.Time) error {
	if len(held) == 0 {
		return nil
	}
	scopes := make([]string, len(held))
	versions := make([]string, len(held))
	for i, h := range held {
		scopes[i], versions[i] = h.Scope, h.Version
	}
	const touch = `
		UPDATE config_snapshot_lkg AS c
		SET compiled_at = $3
		FROM unnest($1::text[], $2::text[]) AS t(scope, version)
		WHERE c.scope = t.scope AND c.version = t.version AND c.compiled_at < $3`
	if _, err := r.pool.Exec(ctx, touch, scopes, versions, compiledAt); err != nil {
		return fmt.Errorf("configsnapshotlkg: touch: %w", err)
	}
	return nil
}

// DeleteVanished removes the rows whose scope is not in keep and that are not
// newer than compiledAt.
func (r *Repository) DeleteVanished(ctx context.Context, keep []string, compiledAt time.Time) error {
	const del = `DELETE FROM config_snapshot_lkg WHERE scope <> ALL($1::text[]) AND compiled_at <= $2`
	if keep == nil {
		keep = []string{}
	}
	if _, err := r.pool.Exec(ctx, del, keep, compiledAt); err != nil {
		return fmt.Errorf("configsnapshotlkg: delete vanished: %w", err)
	}
	return nil
}

// Load returns every persisted record.
func (r *Repository) Load(ctx context.Context) ([]appsnapshot.LKGRecord, error) {
	rows, err := r.pool.Query(ctx, `SELECT scope, version, compiled_at, key_id, payload FROM config_snapshot_lkg`)
	if err != nil {
		return nil, fmt.Errorf("configsnapshotlkg: load: %w", err)
	}
	defer rows.Close()
	var out []appsnapshot.LKGRecord
	for rows.Next() {
		var rec appsnapshot.LKGRecord
		if err := rows.Scan(&rec.Scope, &rec.Version, &rec.CompiledAt, &rec.KeyID, &rec.Payload); err != nil {
			return nil, fmt.Errorf("configsnapshotlkg: scan: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("configsnapshotlkg: iterate: %w", err)
	}
	return out, nil
}
