package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"

	gatewayFKConstraint        = "consumers_gateway_id_fkey"
	consumerBackendFKConstraint = "consumer_backend_backend_id_fkey"
)

var _ domain.Repository = (*Repository)(nil)

type Repository struct {
	conn *database.Connection
}

func NewRepository(conn *database.Connection) *Repository {
	return &Repository{conn: conn}
}

func (r *Repository) Save(ctx context.Context, c *domain.Consumer) error {
	if c == nil {
		return errors.New("consumer repository: nil consumer")
	}
	pathsBytes, methodsBytes, headersBytes, err := marshalJSONColumns(c)
	if err != nil {
		return err
	}
	const insertConsumer = `
		INSERT INTO consumers (
			id, gateway_id, name, type, path, paths, methods, headers,
			strip_path, preserve_host, active, public, retry_attempts,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13,
			$14, $15
		)`
	const insertJoin = `
		INSERT INTO consumer_backend (consumer_id, backend_id)
		VALUES ($1, $2)`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, insertConsumer,
			c.ID, c.GatewayID, c.Name, string(c.Type), c.Path,
			pathsBytes, methodsBytes, headersBytes,
			c.StripPath, c.PreserveHost, c.Active, c.Public, c.RetryAttempts,
			c.CreatedAt, c.UpdatedAt,
		); err != nil {
			return mapPgError(err)
		}
		for _, beID := range c.BackendIDs {
			if _, err := tx.Exec(ctx, insertJoin, c.ID, beID); err != nil {
				return mapPgError(err)
			}
		}
		return nil
	})
}

func (r *Repository) Update(ctx context.Context, c *domain.Consumer) error {
	if c == nil {
		return errors.New("consumer repository: nil consumer")
	}
	pathsBytes, methodsBytes, headersBytes, err := marshalJSONColumns(c)
	if err != nil {
		return err
	}
	const updateConsumer = `
		UPDATE consumers
		   SET name           = $2,
		       type           = $3,
		       path           = $4,
		       paths          = $5,
		       methods        = $6,
		       headers        = $7,
		       strip_path     = $8,
		       preserve_host  = $9,
		       active         = $10,
		       public         = $11,
		       retry_attempts = $12,
		       updated_at     = $13
		 WHERE id = $1`
	const deleteJoins = `
		DELETE FROM consumer_backend
		 WHERE consumer_id = $1
		   AND NOT (backend_id = ANY($2::uuid[]))`
	const insertJoin = `
		INSERT INTO consumer_backend (consumer_id, backend_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, updateConsumer,
			c.ID, c.Name, string(c.Type), c.Path,
			pathsBytes, methodsBytes, headersBytes,
			c.StripPath, c.PreserveHost, c.Active, c.Public, c.RetryAttempts,
			c.UpdatedAt,
		)
		if err != nil {
			return mapPgError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		if _, err := tx.Exec(ctx, deleteJoins, c.ID, c.BackendIDs); err != nil {
			return mapPgError(err)
		}
		for _, beID := range c.BackendIDs {
			if _, err := tx.Exec(ctx, insertJoin, c.ID, beID); err != nil {
				return mapPgError(err)
			}
		}
		return nil
	})
}

func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	const query = `DELETE FROM consumers WHERE id = $1`
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

func (r *Repository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Consumer, error) {
	const query = `
		SELECT c.id, c.gateway_id, c.name, c.type, c.path, c.paths, c.methods, c.headers,
		       c.strip_path, c.preserve_host, c.active, c.public, c.retry_attempts,
		       c.created_at, c.updated_at,
		       COALESCE(
		           array_remove(array_agg(cb.backend_id ORDER BY cb.backend_id), NULL),
		           '{}'
		       )::uuid[] AS backend_ids
		  FROM consumers c
		  LEFT JOIN consumer_backend cb ON cb.consumer_id = c.id
		 WHERE c.id = $1
		 GROUP BY c.id`
	row := r.conn.Pool.QueryRow(ctx, query, id)
	c, err := scanConsumer(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("consumer repository: find: %w", err)
	}
	return c, nil
}

func (r *Repository) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Consumer, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Size < 1 {
		filter.Size = 20
	}
	offset := (filter.Page - 1) * filter.Size

	gatewayParam := nullableUUID(filter.GatewayID)

	const countQuery = `
		SELECT COUNT(*)
		  FROM consumers
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%')`
	var total int
	if err := r.conn.Pool.QueryRow(ctx, countQuery, gatewayParam, filter.NameContains).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("consumer repository: count: %w", err)
	}

	const listQuery = `
		SELECT c.id, c.gateway_id, c.name, c.type, c.path, c.paths, c.methods, c.headers,
		       c.strip_path, c.preserve_host, c.active, c.public, c.retry_attempts,
		       c.created_at, c.updated_at,
		       COALESCE(
		           array_remove(array_agg(cb.backend_id ORDER BY cb.backend_id), NULL),
		           '{}'
		       )::uuid[] AS backend_ids
		  FROM consumers c
		  LEFT JOIN consumer_backend cb ON cb.consumer_id = c.id
		 WHERE ($1::uuid IS NULL OR c.gateway_id = $1)
		   AND ($2 = '' OR lower(c.name) LIKE '%' || lower($2) || '%')
		 GROUP BY c.id
		 ORDER BY c.created_at DESC, c.id
		 LIMIT $3 OFFSET $4`
	rows, err := r.conn.Pool.Query(ctx, listQuery, gatewayParam, filter.NameContains, filter.Size, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("consumer repository: list: %w", err)
	}
	defer rows.Close()

	items := make([]*domain.Consumer, 0, filter.Size)
	for rows.Next() {
		c, err := scanConsumer(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("consumer repository: scan: %w", err)
		}
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("consumer repository: iter: %w", err)
	}
	return items, total, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanConsumer(s rowScanner) (*domain.Consumer, error) {
	c := &domain.Consumer{}
	var (
		pathsRaw, methodsRaw, headersRaw []byte
		consumerType                     string
	)
	if err := s.Scan(
		&c.ID, &c.GatewayID, &c.Name, &consumerType, &c.Path,
		&pathsRaw, &methodsRaw, &headersRaw,
		&c.StripPath, &c.PreserveHost, &c.Active, &c.Public, &c.RetryAttempts,
		&c.CreatedAt, &c.UpdatedAt,
		&c.BackendIDs,
	); err != nil {
		return nil, err
	}
	c.Type = domain.Type(consumerType)
	if len(pathsRaw) > 0 {
		if err := json.Unmarshal(pathsRaw, &c.Paths); err != nil {
			return nil, fmt.Errorf("scan paths: %w", err)
		}
	}
	if len(methodsRaw) > 0 {
		if err := json.Unmarshal(methodsRaw, &c.Methods); err != nil {
			return nil, fmt.Errorf("scan methods: %w", err)
		}
	}
	if len(headersRaw) > 0 {
		if err := json.Unmarshal(headersRaw, &c.Headers); err != nil {
			return nil, fmt.Errorf("scan headers: %w", err)
		}
	}
	if c.BackendIDs == nil {
		c.BackendIDs = []uuid.UUID{}
	}
	return c, nil
}

func marshalJSONColumns(c *domain.Consumer) (paths, methods, headers []byte, err error) {
	paths, err = marshalSlice(c.Paths)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("consumer repository: marshal paths: %w", err)
	}
	methods, err = marshalSlice(c.Methods)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("consumer repository: marshal methods: %w", err)
	}
	headers, err = marshalHeaders(c.Headers)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("consumer repository: marshal headers: %w", err)
	}
	return paths, methods, headers, nil
}

func marshalSlice(v []string) ([]byte, error) {
	if v == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(v)
}

func marshalHeaders(v map[string]string) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(v)
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
			if strings.Contains(pgErr.ConstraintName, gatewayFKConstraint) ||
				strings.Contains(pgErr.Detail, "(gateway_id)") {
				return domain.ErrInvalidGatewayID
			}
			if strings.Contains(pgErr.ConstraintName, consumerBackendFKConstraint) ||
				strings.Contains(pgErr.Detail, "(backend_id)") {
				return domain.ErrInvalidBackendID
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
