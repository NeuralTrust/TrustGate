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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const selectEveryoneColumns = `
	SELECT gateway_id, mode, grants, excluded_groups, created_at, updated_at
	  FROM store_everyone`

var _ domain.EveryoneRepository = (*EveryoneRepository)(nil)

// EveryoneRepository is the pgx-backed store of each gateway's Everyone object.
// It rides the config snapshot, so writes append a change marker.
type EveryoneRepository struct {
	conn   *database.Connection
	outbox outbox.Appender
}

// NewEveryoneRepository builds the repository; appender may be nil.
func NewEveryoneRepository(conn *database.Connection, appender outbox.Appender) *EveryoneRepository {
	return &EveryoneRepository{conn: conn, outbox: appender}
}

func (r *EveryoneRepository) withMarkedTx(ctx context.Context, fn func(pgx.Tx) error) error {
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

// GetEveryone returns the gateway's object, or nil when it has none.
func (r *EveryoneRepository) GetEveryone(ctx context.Context, gatewayID ids.GatewayID) (*domain.Everyone, error) {
	items, err := r.queryEveryone(ctx, selectEveryoneColumns+` WHERE gateway_id = $1`, gatewayID)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, nil
	}
	return items[0], nil
}

// UpsertEveryone creates or replaces the gateway's object.
func (r *EveryoneRepository) UpsertEveryone(ctx context.Context, e *domain.Everyone) error {
	if err := e.Validate(); err != nil {
		return err
	}
	grants, err := json.Marshal(nonNilGrants(e.Grants))
	if err != nil {
		return fmt.Errorf("store everyone repository: encode grants: %w", err)
	}
	excluded, err := json.Marshal(nonNilStrings(e.ExcludedGroups))
	if err != nil {
		return fmt.Errorf("store everyone repository: encode excluded groups: %w", err)
	}
	now := time.Now().UTC()
	created := e.CreatedAt
	if created.IsZero() {
		created = now
	}
	const query = `
		INSERT INTO store_everyone
			(gateway_id, mode, grants, excluded_groups, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (gateway_id) DO UPDATE
			SET mode            = EXCLUDED.mode,
			    grants          = EXCLUDED.grants,
			    excluded_groups = EXCLUDED.excluded_groups,
			    updated_at      = EXCLUDED.updated_at`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, e.GatewayID, e.Mode, grants, excluded, created, now); err != nil {
			return mapEveryonePgError(err)
		}
		return nil
	})
}

// DeleteEveryone removes the gateway's object; missing is not an error.
func (r *EveryoneRepository) DeleteEveryone(ctx context.Context, gatewayID ids.GatewayID) error {
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM store_everyone WHERE gateway_id = $1`, gatewayID); err != nil {
			return mapEveryonePgError(err)
		}
		return nil
	})
}

// ListEveryone pages every gateway's object, ordered by gateway.
func (r *EveryoneRepository) ListEveryone(ctx context.Context, page, size int) ([]*domain.Everyone, int, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 100
	}
	var total int
	if err := r.conn.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM store_everyone`).Scan(&total); err != nil {
		return nil, 0, mapEveryonePgError(err)
	}
	items, err := r.queryEveryone(ctx, selectEveryoneColumns+` ORDER BY gateway_id LIMIT $1 OFFSET $2`, size, (page-1)*size)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *EveryoneRepository) queryEveryone(ctx context.Context, query string, args ...any) ([]*domain.Everyone, error) {
	rows, err := r.conn.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapEveryonePgError(err)
	}
	defer rows.Close()
	out := make([]*domain.Everyone, 0)
	for rows.Next() {
		var (
			e                domain.Everyone
			grants, excluded []byte
		)
		if err := rows.Scan(&e.GatewayID, &e.Mode, &grants, &excluded, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store everyone repository: scan: %w", err)
		}
		if err := json.Unmarshal(grants, &e.Grants); err != nil {
			return nil, fmt.Errorf("store everyone repository: decode grants: %w", err)
		}
		if err := json.Unmarshal(excluded, &e.ExcludedGroups); err != nil {
			return nil, fmt.Errorf("store everyone repository: decode excluded groups: %w", err)
		}
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, mapEveryonePgError(err)
	}
	return out, nil
}

func nonNilGrants(in []domain.EveryoneGrant) []domain.EveryoneGrant {
	if in == nil {
		return []domain.EveryoneGrant{}
	}
	return in
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func mapEveryonePgError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation {
		return fmt.Errorf("%w: unknown gateway", domain.ErrInvalidEveryone)
	}
	return fmt.Errorf("store everyone repository: %w", err)
}
