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

// Package storeaccess holds the pgx-backed MCP Store access repositories (grants, policies). Grants are
// gateway configuration that rides the config snapshot, so every write appends
// a snapshot change marker in the same transaction (like registries / roles).
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

const pgForeignKeyViolation = "23503"

const selectColumns = `
	SELECT gateway_id, catalog_code, registry_id, groups, users, created_at, updated_at
	  FROM store_grants`

var _ domain.Repository = (*Repository)(nil)

type Repository struct {
	conn   *database.Connection
	outbox outbox.Appender
}

func NewRepository(conn *database.Connection, appender outbox.Appender) *Repository {
	return &Repository{conn: conn, outbox: appender}
}

func (r *Repository) withMarkedTx(ctx context.Context, fn func(pgx.Tx) error) error {
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

func (r *Repository) Upsert(ctx context.Context, g *domain.Grant) error {
	if err := g.Validate(); err != nil {
		return err
	}
	// A grant naming nobody is the absence of a grant: delete rather than store
	// an empty row, so readers never see "granted to nobody" entries.
	if g.IsEmpty() {
		return r.Delete(ctx, g.GatewayID, g.CatalogCode, g.RegistryID)
	}
	groups, err := json.Marshal(nonNil(g.Groups))
	if err != nil {
		return fmt.Errorf("store grant repository: marshal groups: %w", err)
	}
	users, err := json.Marshal(nonNil(g.Users))
	if err != nil {
		return fmt.Errorf("store grant repository: marshal users: %w", err)
	}
	now := time.Now().UTC()
	created := g.CreatedAt
	if created.IsZero() {
		created = now
	}
	const query = `
		INSERT INTO store_grants
			(gateway_id, catalog_code, registry_id, groups, users, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (gateway_id, catalog_code, registry_id) DO UPDATE
			SET groups     = EXCLUDED.groups,
			    users      = EXCLUDED.users,
			    updated_at = EXCLUDED.updated_at`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query,
			g.GatewayID, g.CatalogCode, g.RegistryID, groups, users, created, now,
		); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *Repository) Delete(ctx context.Context, gatewayID ids.GatewayID, code string, registryID ids.RegistryID) error {
	const query = `
		DELETE FROM store_grants
		 WHERE gateway_id = $1 AND catalog_code = $2 AND registry_id = $3`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, gatewayID, code, registryID); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *Repository) DeleteByRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) error {
	if registryID.IsNil() {
		return nil
	}
	const query = `
		DELETE FROM store_grants
		 WHERE gateway_id = $1 AND registry_id = $2`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, gatewayID, registryID); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *Repository) ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Grant, error) {
	const query = selectColumns + `
		WHERE gateway_id = $1
		ORDER BY catalog_code, registry_id`
	return r.queryList(ctx, query, gatewayID)
}

func (r *Repository) List(ctx context.Context, page, size int) ([]*domain.Grant, int, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 100
	}
	var total int
	if err := r.conn.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM store_grants`).Scan(&total); err != nil {
		return nil, 0, mapPgError(err)
	}
	const query = selectColumns + `
		ORDER BY gateway_id, catalog_code, registry_id
		LIMIT $1 OFFSET $2`
	items, err := r.queryList(ctx, query, size, (page-1)*size)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *Repository) queryList(ctx context.Context, query string, args ...any) ([]*domain.Grant, error) {
	rows, err := r.conn.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()
	out := make([]*domain.Grant, 0)
	for rows.Next() {
		var (
			g      domain.Grant
			groups []byte
			users  []byte
		)
		if err := rows.Scan(&g.GatewayID, &g.CatalogCode, &g.RegistryID, &groups, &users, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store grant repository: scan: %w", err)
		}
		if err := json.Unmarshal(groups, &g.Groups); err != nil {
			return nil, fmt.Errorf("store grant repository: unmarshal groups: %w", err)
		}
		if err := json.Unmarshal(users, &g.Users); err != nil {
			return nil, fmt.Errorf("store grant repository: unmarshal users: %w", err)
		}
		out = append(out, &g)
	}
	if err := rows.Err(); err != nil {
		return nil, mapPgError(err)
	}
	return out, nil
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func mapPgError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation {
		return fmt.Errorf("%w: unknown gateway", domain.ErrInvalidGrant)
	}
	return fmt.Errorf("store grant repository: %w", err)
}
