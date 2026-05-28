package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
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

func (r *Repository) Save(ctx context.Context, b *domain.Backend) error {
	if b == nil {
		return errors.New("backend repository: nil backend")
	}
	targetsBytes, err := json.Marshal(b.Targets)
	if err != nil {
		return fmt.Errorf("backend repository: marshal targets: %w", err)
	}
	embeddingBytes, err := marshalEmbedding(b.EmbeddingConfig)
	if err != nil {
		return fmt.Errorf("backend repository: marshal embedding_config: %w", err)
	}
	healthChecksBytes, err := marshalHealthChecks(b.HealthChecks)
	if err != nil {
		return fmt.Errorf("backend repository: marshal health_checks: %w", err)
	}
	const query = `
		INSERT INTO backends (id, gateway_id, name, algorithm, targets, embedding_config, health_checks, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query,
			b.ID, b.GatewayID, b.Name, b.Algorithm, targetsBytes, embeddingBytes, healthChecksBytes, b.CreatedAt, b.UpdatedAt,
		); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *Repository) Update(ctx context.Context, b *domain.Backend) error {
	if b == nil {
		return errors.New("backend repository: nil backend")
	}
	targetsBytes, err := json.Marshal(b.Targets)
	if err != nil {
		return fmt.Errorf("backend repository: marshal targets: %w", err)
	}
	embeddingBytes, err := marshalEmbedding(b.EmbeddingConfig)
	if err != nil {
		return fmt.Errorf("backend repository: marshal embedding_config: %w", err)
	}
	healthChecksBytes, err := marshalHealthChecks(b.HealthChecks)
	if err != nil {
		return fmt.Errorf("backend repository: marshal health_checks: %w", err)
	}
	const query = `
		UPDATE backends
		   SET name             = $2,
		       algorithm        = $3,
		       targets          = $4,
		       embedding_config = $5,
		       health_checks    = $6,
		       updated_at       = $7
		 WHERE id = $1`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query,
			b.ID, b.Name, b.Algorithm, targetsBytes, embeddingBytes, healthChecksBytes, b.UpdatedAt,
		)
		if err != nil {
			return mapPgError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	const query = `DELETE FROM backends WHERE id = $1`
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

func (r *Repository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Backend, error) {
	const query = `
		SELECT id, gateway_id, name, algorithm, targets, embedding_config, health_checks, created_at, updated_at
		  FROM backends
		 WHERE id = $1`
	row := r.conn.Pool.QueryRow(ctx, query, id)
	b, err := scanBackend(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("backend repository: find: %w", err)
	}
	return b, nil
}

func (r *Repository) FindByIDs(ctx context.Context, gatewayID uuid.UUID, ids []uuid.UUID) ([]*domain.Backend, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	const query = `
		SELECT id, gateway_id, name, algorithm, targets, embedding_config, health_checks, created_at, updated_at
		  FROM backends
		 WHERE gateway_id = $1
		   AND id = ANY($2::uuid[])`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID, ids)
	if err != nil {
		return nil, fmt.Errorf("backend repository: find by ids: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Backend, 0, len(ids))
	for rows.Next() {
		b, err := scanBackend(rows)
		if err != nil {
			return nil, fmt.Errorf("backend repository: scan: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backend repository: iter: %w", err)
	}
	return out, nil
}

func (r *Repository) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Backend, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Size < 1 {
		filter.Size = 20
	}
	offset := (filter.Page - 1) * filter.Size

	const countQuery = `
		SELECT COUNT(*)
		  FROM backends
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%')`

	gatewayParam := nullableUUID(filter.GatewayID)

	var total int
	if err := r.conn.Pool.QueryRow(ctx, countQuery, gatewayParam, filter.NameContains).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("backend repository: count: %w", err)
	}

	const listQuery = `
		SELECT id, gateway_id, name, algorithm, targets, embedding_config, health_checks, created_at, updated_at
		  FROM backends
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%')
		 ORDER BY created_at DESC, id
		 LIMIT $3 OFFSET $4`
	rows, err := r.conn.Pool.Query(ctx, listQuery, gatewayParam, filter.NameContains, filter.Size, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("backend repository: list: %w", err)
	}
	defer rows.Close()

	items := make([]*domain.Backend, 0, filter.Size)
	for rows.Next() {
		b, err := scanBackend(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("backend repository: scan: %w", err)
		}
		items = append(items, b)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("backend repository: iter: %w", err)
	}
	return items, total, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanBackend(s rowScanner) (*domain.Backend, error) {
	b := &domain.Backend{}
	var targetsRaw, embeddingRaw, healthChecksRaw []byte
	if err := s.Scan(
		&b.ID, &b.GatewayID, &b.Name, &b.Algorithm,
		&targetsRaw, &embeddingRaw, &healthChecksRaw,
		&b.CreatedAt, &b.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if len(targetsRaw) > 0 {
		if err := json.Unmarshal(targetsRaw, &b.Targets); err != nil {
			return nil, fmt.Errorf("scan targets: %w", err)
		}
	}
	if b.Targets == nil {
		b.Targets = domain.Targets{}
	}

	if len(embeddingRaw) > 0 {
		var ec domain.EmbeddingConfig
		if err := json.Unmarshal(embeddingRaw, &ec); err != nil {
			return nil, fmt.Errorf("scan embedding_config: %w", err)
		}
		b.EmbeddingConfig = &ec
	}

	if len(healthChecksRaw) > 0 {
		var hc domain.HealthChecks
		if err := json.Unmarshal(healthChecksRaw, &hc); err != nil {
			return nil, fmt.Errorf("scan health_checks: %w", err)
		}
		b.HealthChecks = &hc
	}

	return b, nil
}

func marshalEmbedding(e *domain.EmbeddingConfig) ([]byte, error) {
	if e == nil {
		return nil, nil
	}
	return json.Marshal(e)
}

func marshalHealthChecks(h *domain.HealthChecks) ([]byte, error) {
	if h == nil {
		return nil, nil
	}
	return json.Marshal(h)
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
