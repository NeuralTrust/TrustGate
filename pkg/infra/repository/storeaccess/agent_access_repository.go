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

const selectAgentAccessColumns = `
	SELECT gateway_id, principal_type, principal_id, mode, registry_ids, created_at, updated_at
	  FROM store_agent_access`

var _ domain.AgentAccessRepository = (*AgentAccessRepository)(nil)

// AgentAccessRepository is the pgx-backed store of who may call which A2A
// agents from the Employee portal. Rows ride the config snapshot, so writes
// append a change marker.
type AgentAccessRepository struct {
	conn   *database.Connection
	outbox outbox.Appender
}

// NewAgentAccessRepository builds the repository; appender may be nil.
func NewAgentAccessRepository(conn *database.Connection, appender outbox.Appender) *AgentAccessRepository {
	return &AgentAccessRepository{conn: conn, outbox: appender}
}

func (r *AgentAccessRepository) withGatewayMarkedTx(ctx context.Context, gatewayID ids.GatewayID, fn func(pgx.Tx) error) error {
	return outbox.WithGatewayMarkedTx(ctx, r.conn, r.outbox, gatewayID, fn)
}

func (r *AgentAccessRepository) UpsertAgentAccess(ctx context.Context, a *domain.AgentAccess) error {
	if err := a.Validate(); err != nil {
		return err
	}
	registries := a.RegistryIDs
	if registries == nil {
		registries = []ids.RegistryID{}
	}
	encoded, err := json.Marshal(registries)
	if err != nil {
		return fmt.Errorf("store agent access repository: encode registry ids: %w", err)
	}
	now := time.Now().UTC()
	created := a.CreatedAt
	if created.IsZero() {
		created = now
	}
	const query = `
		INSERT INTO store_agent_access
			(gateway_id, principal_type, principal_id, mode, registry_ids, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (gateway_id, principal_type, principal_id) DO UPDATE
			SET mode         = EXCLUDED.mode,
			    registry_ids = EXCLUDED.registry_ids,
			    updated_at   = EXCLUDED.updated_at`
	return r.withGatewayMarkedTx(ctx, a.GatewayID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, a.GatewayID, string(a.PrincipalType), a.PrincipalID, a.Mode, encoded, created, now); err != nil {
			return mapAgentAccessPgError(err)
		}
		return nil
	})
}

func (r *AgentAccessRepository) DeleteAgentAccess(ctx context.Context, gatewayID ids.GatewayID, principalType domain.PrincipalType, principalID string) error {
	const query = `
		DELETE FROM store_agent_access
		 WHERE gateway_id = $1 AND principal_type = $2 AND principal_id = $3`
	return r.withGatewayMarkedTx(ctx, gatewayID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, gatewayID, string(principalType), principalID); err != nil {
			return mapAgentAccessPgError(err)
		}
		return nil
	})
}

func (r *AgentAccessRepository) PruneAgentRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) error {
	const query = `
		UPDATE store_agent_access
		   SET registry_ids = registry_ids - $2::text, updated_at = $3
		 WHERE gateway_id = $1 AND registry_ids ? $2::text`
	return r.withGatewayMarkedTx(ctx, gatewayID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, gatewayID, registryID.String(), time.Now().UTC()); err != nil {
			return mapAgentAccessPgError(err)
		}
		return nil
	})
}

func (r *AgentAccessRepository) ListAgentAccessByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.AgentAccess, error) {
	return r.query(ctx, selectAgentAccessColumns+` WHERE gateway_id = $1 ORDER BY principal_type, principal_id`, gatewayID)
}

func (r *AgentAccessRepository) ListAgentAccess(ctx context.Context, page, size int) ([]*domain.AgentAccess, int, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 100
	}
	var total int
	if err := database.Reader(ctx, r.conn.Pool).QueryRow(ctx, `SELECT COUNT(*) FROM store_agent_access`).Scan(&total); err != nil {
		return nil, 0, mapAgentAccessPgError(err)
	}
	items, err := r.query(ctx, selectAgentAccessColumns+`
		ORDER BY gateway_id, principal_type, principal_id
		LIMIT $1 OFFSET $2`, size, (page-1)*size)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *AgentAccessRepository) query(ctx context.Context, query string, args ...any) ([]*domain.AgentAccess, error) {
	rows, err := database.Reader(ctx, r.conn.Pool).Query(ctx, query, args...)
	if err != nil {
		return nil, mapAgentAccessPgError(err)
	}
	defer rows.Close()
	out := make([]*domain.AgentAccess, 0)
	for rows.Next() {
		var (
			a             domain.AgentAccess
			principalType string
			registries    []byte
		)
		if err := rows.Scan(&a.GatewayID, &principalType, &a.PrincipalID, &a.Mode, &registries, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store agent access repository: scan: %w", err)
		}
		if err := json.Unmarshal(registries, &a.RegistryIDs); err != nil {
			return nil, fmt.Errorf("store agent access repository: decode registry ids: %w", err)
		}
		if len(a.RegistryIDs) == 0 {
			a.RegistryIDs = nil
		}
		a.PrincipalType = domain.PrincipalType(principalType)
		out = append(out, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, mapAgentAccessPgError(err)
	}
	return out, nil
}

func mapAgentAccessPgError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation {
		return fmt.Errorf("%w: unknown gateway", domain.ErrInvalidAgentAccess)
	}
	return fmt.Errorf("store agent access repository: %w", err)
}
