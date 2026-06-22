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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

const policySelectColumns = `
		SELECT p.id, p.gateway_id, p.name, p.slug, p.enabled, p.global, p.priority, p.parallel, p.settings, p.stages, p.created_at, p.updated_at, p.description, p.mode,
		       COALESCE((SELECT array_agg(cp.consumer_id ORDER BY cp.consumer_id)
		                   FROM consumer_policy cp WHERE cp.policy_id = p.id), '{}')::uuid[] AS consumer_ids`

var _ domain.Repository = (*Repository)(nil)

type Repository struct {
	conn *database.Connection
}

func NewRepository(conn *database.Connection) *Repository {
	return &Repository{conn: conn}
}

func (r *Repository) Save(ctx context.Context, p *domain.Policy) error {
	if p == nil {
		return errors.New("policy repository: nil policy")
	}
	settingsBytes, err := marshalSettings(p.Settings)
	if err != nil {
		return fmt.Errorf("policy repository: marshal settings: %w", err)
	}
	stagesBytes, err := marshalStages(p.Stages)
	if err != nil {
		return fmt.Errorf("policy repository: marshal stages: %w", err)
	}
	const query = `
		INSERT INTO policies (id, gateway_id, name, slug, enabled, global, priority, parallel, settings, stages, created_at, updated_at, description, mode)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	if _, err := r.conn.Pool.Exec(ctx, query,
		p.ID, p.GatewayID, p.Name, p.Slug, p.Enabled, p.Global, p.Priority, p.Parallel,
		settingsBytes, stagesBytes, p.CreatedAt, p.UpdatedAt, p.Description, string(p.Mode.Normalize()),
	); err != nil {
		return mapPgError(err)
	}
	return nil
}

func (r *Repository) Update(ctx context.Context, p *domain.Policy) error {
	if p == nil {
		return errors.New("policy repository: nil policy")
	}
	settingsBytes, err := marshalSettings(p.Settings)
	if err != nil {
		return fmt.Errorf("policy repository: marshal settings: %w", err)
	}
	stagesBytes, err := marshalStages(p.Stages)
	if err != nil {
		return fmt.Errorf("policy repository: marshal stages: %w", err)
	}
	const query = `
		UPDATE policies
		   SET name        = $2,
		       slug        = $3,
		       enabled     = $4,
		       global      = $5,
		       priority    = $6,
		       parallel    = $7,
		       settings    = $8,
		       stages      = $9,
		       updated_at  = $10,
		       description = $11,
		       mode        = $12
		 WHERE id = $1 AND gateway_id = $13`
	cmd, err := r.conn.Pool.Exec(ctx, query,
		p.ID, p.Name, p.Slug, p.Enabled, p.Global, p.Priority, p.Parallel,
		settingsBytes, stagesBytes, p.UpdatedAt, p.Description, string(p.Mode.Normalize()), p.GatewayID,
	)
	if err != nil {
		return mapPgError(err)
	}
	if cmd.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *Repository) SetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID, global bool) error {
	const query = `UPDATE policies SET global = $2, updated_at = now() WHERE id = $1 AND gateway_id = $3`
	cmd, err := r.conn.Pool.Exec(ctx, query, id, global, gatewayID)
	if err != nil {
		return mapPgError(err)
	}
	if cmd.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *Repository) Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) error {
	const query = `DELETE FROM policies WHERE id = $1 AND gateway_id = $2`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query, id, gatewayID)
		if err != nil {
			return mapPgDeleteError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *Repository) FindByID(ctx context.Context, id ids.PolicyID) (*domain.Policy, error) {
	query := policySelectColumns + `
		  FROM policies p
		 WHERE p.id = $1`
	row := r.conn.Pool.QueryRow(ctx, query, id)
	p, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("policy repository: find: %w", err)
	}
	return p, nil
}

func (r *Repository) FindByIDs(ctx context.Context, gatewayID ids.GatewayID, policyIDs []ids.PolicyID) ([]*domain.Policy, error) {
	if len(policyIDs) == 0 {
		return nil, nil
	}
	query := policySelectColumns + `
		  FROM policies p
		 WHERE p.gateway_id = $1
		   AND p.id = ANY($2::uuid[])`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID.UUID(), ids.ToUUIDs(policyIDs))
	if err != nil {
		return nil, fmt.Errorf("policy repository: find by ids: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Policy, 0, len(policyIDs))
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("policy repository: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policy repository: iter: %w", err)
	}
	return out, nil
}

func (r *Repository) ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Policy, error) {
	query := policySelectColumns + `
		  FROM policies p
		 WHERE p.gateway_id = $1
		 ORDER BY p.priority, p.created_at, p.id`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID.UUID())
	if err != nil {
		return nil, fmt.Errorf("policy repository: list by gateway: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Policy, 0)
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("policy repository: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policy repository: iter: %w", err)
	}
	return out, nil
}

func (r *Repository) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Policy, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Size < 1 {
		filter.Size = 20
	}
	offset := (filter.Page - 1) * filter.Size

	const countQuery = `
		SELECT COUNT(*)
		  FROM policies
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%')`

	gatewayParam := nullableUUID(filter.GatewayID.UUID())

	var total int
	if err := r.conn.Pool.QueryRow(ctx, countQuery, gatewayParam, filter.NameContains).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("policy repository: count: %w", err)
	}

	listQuery := policySelectColumns + `
		  FROM policies p
		 WHERE ($1::uuid IS NULL OR p.gateway_id = $1)
		   AND ($2 = '' OR lower(p.name) LIKE '%' || lower($2) || '%')
		 ORDER BY p.created_at DESC, p.id
		 LIMIT $3 OFFSET $4`
	rows, err := r.conn.Pool.Query(ctx, listQuery, gatewayParam, filter.NameContains, filter.Size, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("policy repository: list: %w", err)
	}
	defer rows.Close()

	items := make([]*domain.Policy, 0, filter.Size)
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("policy repository: scan: %w", err)
		}
		items = append(items, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("policy repository: iter: %w", err)
	}
	return items, total, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanPolicy(s rowScanner) (*domain.Policy, error) {
	p := &domain.Policy{}
	var settingsRaw []byte
	var stagesRaw []byte
	var consumerIDs []uuid.UUID
	var mode string
	if err := s.Scan(
		&p.ID, &p.GatewayID, &p.Name, &p.Slug, &p.Enabled, &p.Global, &p.Priority, &p.Parallel,
		&settingsRaw, &stagesRaw,
		&p.CreatedAt, &p.UpdatedAt, &p.Description, &mode,
		&consumerIDs,
	); err != nil {
		return nil, err
	}
	p.Mode = domain.Mode(mode).Normalize()
	p.ConsumerIDs = ids.FromUUIDs[ids.ConsumerKind](consumerIDs)

	if len(settingsRaw) > 0 {
		if err := json.Unmarshal(settingsRaw, &p.Settings); err != nil {
			return nil, fmt.Errorf("scan settings: %w", err)
		}
	}
	if len(stagesRaw) > 0 {
		if err := json.Unmarshal(stagesRaw, &p.Stages); err != nil {
			return nil, fmt.Errorf("scan stages: %w", err)
		}
	}
	return p, nil
}

func marshalSettings(s map[string]any) ([]byte, error) {
	if len(s) == 0 {
		return []byte("{}"), nil
	}
	return json.Marshal(s)
}

func marshalStages(stages []domain.Stage) ([]byte, error) {
	if len(stages) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(stages)
}

func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func mapPgError(err error) error {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		switch pgErr.Code {
		case pgUniqueViolation:
			return domain.ErrAlreadyExists
		case pgForeignKeyViolation:
			if strings.Contains(pgErr.ConstraintName, "consumer_id") ||
				strings.Contains(pgErr.Detail, "(consumer_id)") {
				return domain.ErrInvalidConsumerID
			}
			return domain.ErrInvalidGatewayID
		}
	}
	return err
}

func mapPgDeleteError(err error) error {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		if pgErr.Code == pgForeignKeyViolation {
			return domain.ErrHasDependents
		}
	}
	return err
}
