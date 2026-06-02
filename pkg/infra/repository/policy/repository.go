package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

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
	pluginsBytes, err := marshalPlugins(p.Plugins)
	if err != nil {
		return fmt.Errorf("policy repository: marshal plugins: %w", err)
	}
	const query = `
		INSERT INTO policies (id, gateway_id, name, plugins, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query,
			p.ID, p.GatewayID, p.Name, pluginsBytes, p.CreatedAt, p.UpdatedAt,
		); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *Repository) Update(ctx context.Context, p *domain.Policy) error {
	if p == nil {
		return errors.New("policy repository: nil policy")
	}
	pluginsBytes, err := marshalPlugins(p.Plugins)
	if err != nil {
		return fmt.Errorf("policy repository: marshal plugins: %w", err)
	}
	const query = `
		UPDATE policies
		   SET name       = $2,
		       plugins    = $3,
		       updated_at = $4
		 WHERE id = $1`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query, p.ID, p.Name, pluginsBytes, p.UpdatedAt)
		if err != nil {
			return mapPgError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *Repository) Delete(ctx context.Context, id ids.PolicyID) error {
	const query = `DELETE FROM policies WHERE id = $1`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query, id)
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
	const query = `
		SELECT id, gateway_id, name, plugins, created_at, updated_at
		  FROM policies
		 WHERE id = $1`
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
	const query = `
		SELECT id, gateway_id, name, plugins, created_at, updated_at
		  FROM policies
		 WHERE gateway_id = $1
		   AND id = ANY($2::uuid[])`
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

	const listQuery = `
		SELECT id, gateway_id, name, plugins, created_at, updated_at
		  FROM policies
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%')
		 ORDER BY created_at DESC, id
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
	var pluginsRaw []byte
	if err := s.Scan(
		&p.ID, &p.GatewayID, &p.Name,
		&pluginsRaw,
		&p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if len(pluginsRaw) > 0 {
		if err := json.Unmarshal(pluginsRaw, &p.Plugins); err != nil {
			return nil, fmt.Errorf("scan plugins: %w", err)
		}
	}
	if p.Plugins == nil {
		p.Plugins = domain.Plugins{}
	}
	return p, nil
}

func marshalPlugins(p domain.Plugins) ([]byte, error) {
	if len(p) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(p)
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
