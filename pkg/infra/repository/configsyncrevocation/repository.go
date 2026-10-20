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

// Package configsyncrevocation is the pgx-backed store of config-sync token
// revocations.
package configsyncrevocation

import (
	"context"
	"fmt"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

var _ domain.Store = (*Repository)(nil)

const (
	insertJTIs = `
		INSERT INTO config_sync_token_revocations (scope, jti)
		SELECT $1::text, unnest($2::text[])
		ON CONFLICT (scope, jti) DO NOTHING`
	upsertMark = `
		INSERT INTO config_sync_scope_issued_before (scope, issued_before)
		VALUES ($1, $2)
		ON CONFLICT (scope) DO UPDATE
		SET issued_before = GREATEST(config_sync_scope_issued_before.issued_before, EXCLUDED.issued_before),
		    updated_at = now()`
	selectJTIs  = `SELECT scope, jti FROM config_sync_token_revocations`
	selectMarks = `SELECT scope, issued_before FROM config_sync_scope_issued_before`
)

// Repository implements domain.Store over config_sync_token_revocations and
// config_sync_scope_issued_before.
type Repository struct {
	conn *database.Connection
}

// NewRepository builds the repository from the shared connection.
func NewRepository(conn *database.Connection) *Repository {
	return &Repository{conn: conn}
}

// Apply records one revocation in a single transaction. Repeating a jti is a
// no-op, and an issued-before mark never moves backwards.
func (r *Repository) Apply(ctx context.Context, rev domain.Revocation) error {
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if len(rev.JTIs) > 0 {
			if _, err := tx.Exec(ctx, insertJTIs, rev.Scope, rev.JTIs); err != nil {
				return fmt.Errorf("configsyncrevocation: insert jtis: %w", err)
			}
		}
		if rev.IssuedBefore > 0 {
			if _, err := tx.Exec(ctx, upsertMark, rev.Scope, rev.IssuedBefore); err != nil {
				return fmt.Errorf("configsyncrevocation: upsert issued_before: %w", err)
			}
		}
		return nil
	})
}

// Load returns every stored token revocation and every issued-before mark.
func (r *Repository) Load(ctx context.Context) (domain.Revocations, error) {
	if r.conn == nil || r.conn.Pool == nil {
		return domain.Revocations{}, fmt.Errorf("configsyncrevocation: nil connection")
	}
	var out domain.Revocations

	jtis, err := r.conn.Pool.Query(ctx, selectJTIs)
	if err != nil {
		return domain.Revocations{}, fmt.Errorf("configsyncrevocation: load jtis: %w", err)
	}
	defer jtis.Close()
	for jtis.Next() {
		var rev domain.JTIRevocation
		if err := jtis.Scan(&rev.Scope, &rev.JTI); err != nil {
			return domain.Revocations{}, fmt.Errorf("configsyncrevocation: scan jti: %w", err)
		}
		out.JTIs = append(out.JTIs, rev)
	}
	if err := jtis.Err(); err != nil {
		return domain.Revocations{}, fmt.Errorf("configsyncrevocation: iterate jtis: %w", err)
	}

	marks, err := r.conn.Pool.Query(ctx, selectMarks)
	if err != nil {
		return domain.Revocations{}, fmt.Errorf("configsyncrevocation: load marks: %w", err)
	}
	defer marks.Close()
	for marks.Next() {
		var mark domain.IssuedBeforeMark
		if err := marks.Scan(&mark.Scope, &mark.IssuedBefore); err != nil {
			return domain.Revocations{}, fmt.Errorf("configsyncrevocation: scan mark: %w", err)
		}
		out.Marks = append(out.Marks, mark)
	}
	if err := marks.Err(); err != nil {
		return domain.Revocations{}, fmt.Errorf("configsyncrevocation: iterate marks: %w", err)
	}
	return out, nil
}
