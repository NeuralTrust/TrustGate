// Package gateway is the pgx-backed implementation of the gateway
// domain repository. It only knows about SQL and uuid; domain
// invariants stay in pkg/domain/gateway.
package gateway

import (
	"context"
	"errors"
	"fmt"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

// Repository persists Gateway aggregates against Postgres via pgxpool.
type Repository struct {
	conn *database.Connection
}

// NewRepository wires a fresh repository against the given connection.
// It returns the concrete struct so dig can also bind it as
// domain.Repository in the entity module.
func NewRepository(conn *database.Connection) *Repository {
	return &Repository{conn: conn}
}

// Save inserts a new gateway row. On unique-name conflict it returns
// domain.ErrAlreadyExists.
func (r *Repository) Save(ctx context.Context, g *domain.Gateway) error {
	if g == nil {
		return errors.New("gateway repository: nil gateway")
	}
	const query = `
		INSERT INTO gateways (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, g.ID, g.Name, g.Description, g.CreatedAt, g.UpdatedAt); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

// Update overwrites name + description + updated_at for an existing
// gateway. Returns domain.ErrNotFound if no row matches the ID.
func (r *Repository) Update(ctx context.Context, g *domain.Gateway) error {
	if g == nil {
		return errors.New("gateway repository: nil gateway")
	}
	const query = `
		UPDATE gateways
		   SET name = $2,
		       description = $3,
		       updated_at = $4
		 WHERE id = $1`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query, g.ID, g.Name, g.Description, g.UpdatedAt)
		if err != nil {
			return mapPgError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

// Delete removes a gateway by ID. Returns domain.ErrNotFound when
// missing and domain.ErrHasDependents when FK constraints (backends)
// reference it.
func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	const query = `DELETE FROM gateways WHERE id = $1`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query, id)
		if err != nil {
			return mapPgError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

// FindByID loads a gateway by primary key.
func (r *Repository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Gateway, error) {
	const query = `
		SELECT id, name, description, created_at, updated_at
		  FROM gateways
		 WHERE id = $1`
	row := r.conn.Pool.QueryRow(ctx, query, id)
	g, err := scanGateway(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("gateway repository: find: %w", err)
	}
	return g, nil
}

// List returns gateways matching the filter together with the total
// count of matches (independent of pagination).
func (r *Repository) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Gateway, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Size < 1 {
		filter.Size = 20
	}
	offset := (filter.Page - 1) * filter.Size

	const countQuery = `
		SELECT COUNT(*)
		  FROM gateways
		 WHERE ($1 = '' OR lower(name) LIKE '%' || lower($1) || '%')`
	var total int
	if err := r.conn.Pool.QueryRow(ctx, countQuery, filter.NameContains).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("gateway repository: count: %w", err)
	}

	const listQuery = `
		SELECT id, name, description, created_at, updated_at
		  FROM gateways
		 WHERE ($1 = '' OR lower(name) LIKE '%' || lower($1) || '%')
		 ORDER BY created_at DESC, id
		 LIMIT $2 OFFSET $3`
	rows, err := r.conn.Pool.Query(ctx, listQuery, filter.NameContains, filter.Size, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("gateway repository: list: %w", err)
	}
	defer rows.Close()

	items := make([]*domain.Gateway, 0, filter.Size)
	for rows.Next() {
		g, err := scanGateway(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("gateway repository: scan: %w", err)
		}
		items = append(items, g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("gateway repository: iter: %w", err)
	}
	return items, total, nil
}

// rowScanner is the minimal contract shared by pgx.Row and pgx.Rows so
// scanGateway can read from both QueryRow and Query results.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanGateway(s rowScanner) (*domain.Gateway, error) {
	g := &domain.Gateway{}
	if err := s.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
		return nil, err
	}
	return g, nil
}

func mapPgError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgUniqueViolation:
			return domain.ErrAlreadyExists
		case pgForeignKeyViolation:
			return domain.ErrHasDependents
		}
	}
	return err
}
