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

// Package keygroup is the pgx store of the budgets of directory groups' keys.
package keygroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pgForeignKeyViolation = "23503"

	budgetColumns = `gateway_id, group_id, monthly_limit_usd, member_monthly_limit_usd, member_overrides, action, created_at, updated_at`
)

var _ domain.Repository = (*BudgetRepository)(nil)

// BudgetRepository stores one budget per (gateway, group). Budgets ride the
// config snapshot, so every write commits a change marker with it.
type BudgetRepository struct {
	conn   *database.Connection
	outbox outbox.Appender
}

// NewBudgetRepository builds the repository over the shared connection.
func NewBudgetRepository(conn *database.Connection, appender outbox.Appender) *BudgetRepository {
	return &BudgetRepository{conn: conn, outbox: appender}
}

func (r *BudgetRepository) withMarkedTx(ctx context.Context, fn func(pgx.Tx) error) error {
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

func (r *BudgetRepository) Upsert(ctx context.Context, b *domain.Budget) (*domain.Budget, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	overrides, err := overridesParam(b.MemberOverrides)
	if err != nil {
		return nil, err
	}
	const query = `
		INSERT INTO key_group_budgets (` + budgetColumns + `)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (gateway_id, group_id) DO UPDATE
			SET monthly_limit_usd        = EXCLUDED.monthly_limit_usd,
			    member_monthly_limit_usd = EXCLUDED.member_monthly_limit_usd,
			    member_overrides         = EXCLUDED.member_overrides,
			    action                   = EXCLUDED.action,
			    updated_at               = EXCLUDED.updated_at
		RETURNING ` + budgetColumns
	var stored *domain.Budget
	err = r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		var scanErr error
		stored, scanErr = scanBudget(tx.QueryRow(ctx, query,
			b.GatewayID, b.GroupID, b.MonthlyLimitUSD, b.MemberMonthlyLimitUSD, overrides, b.Action, b.CreatedAt, b.UpdatedAt,
		))
		if scanErr != nil {
			return mapPgError(scanErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return stored, nil
}

func (r *BudgetRepository) Delete(ctx context.Context, gatewayID ids.GatewayID, groupID string) error {
	const query = `DELETE FROM key_group_budgets WHERE gateway_id = $1 AND group_id = $2`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query, gatewayID, groupID)
		if err != nil {
			return mapPgError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *BudgetRepository) ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Budget, error) {
	const query = `
		SELECT ` + budgetColumns + `
		  FROM key_group_budgets
		 WHERE gateway_id = $1
		 ORDER BY group_id`
	return r.query(ctx, query, gatewayID)
}

func (r *BudgetRepository) List(ctx context.Context, page, size int) ([]*domain.Budget, int, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 100
	}
	var total int
	if err := r.conn.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM key_group_budgets`).Scan(&total); err != nil {
		return nil, 0, mapPgError(err)
	}
	const query = `
		SELECT ` + budgetColumns + `
		  FROM key_group_budgets
		 ORDER BY gateway_id, group_id
		 LIMIT $1 OFFSET $2`
	items, err := r.query(ctx, query, size, (page-1)*size)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *BudgetRepository) query(ctx context.Context, query string, args ...any) ([]*domain.Budget, error) {
	rows, err := r.conn.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()
	out := make([]*domain.Budget, 0)
	for rows.Next() {
		b, err := scanBudget(rows)
		if err != nil {
			return nil, fmt.Errorf("key group budget repository: scan: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, mapPgError(err)
	}
	return out, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanBudget(s rowScanner) (*domain.Budget, error) {
	var (
		b         domain.Budget
		overrides []byte
	)
	if err := s.Scan(&b.GatewayID, &b.GroupID, &b.MonthlyLimitUSD, &b.MemberMonthlyLimitUSD, &overrides, &b.Action, &b.CreatedAt, &b.UpdatedAt); err != nil {
		return nil, err
	}
	if len(overrides) > 0 {
		if err := json.Unmarshal(overrides, &b.MemberOverrides); err != nil {
			return nil, fmt.Errorf("scan member overrides: %w", err)
		}
	}
	return &b, nil
}

func overridesParam(overrides map[string]float64) (any, error) {
	if len(overrides) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(overrides)
	if err != nil {
		return nil, fmt.Errorf("key group budget repository: marshal member overrides: %w", err)
	}
	return raw, nil
}

func mapPgError(err error) error {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgForeignKeyViolation {
		return fmt.Errorf("%w: unknown gateway", domain.ErrInvalidBudget)
	}
	return fmt.Errorf("key group budget repository: %w", err)
}
