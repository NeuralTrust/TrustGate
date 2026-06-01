package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
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

func (r *Repository) Save(ctx context.Context, g *domain.Gateway) error {
	if g == nil {
		return errors.New("gateway repository: nil gateway")
	}
	telemetryBytes, err := marshalJSON(g.Telemetry)
	if err != nil {
		return fmt.Errorf("gateway repository: marshal telemetry: %w", err)
	}
	clientTLSBytes, err := marshalJSON(g.ClientTLSConfig)
	if err != nil {
		return fmt.Errorf("gateway repository: marshal client_tls: %w", err)
	}
	sessionBytes, err := marshalJSON(g.SessionConfig)
	if err != nil {
		return fmt.Errorf("gateway repository: marshal session_config: %w", err)
	}
	const query = `
		INSERT INTO gateways (id, name, status, telemetry, client_tls, session_config, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query,
			g.ID, g.Name, g.Status, telemetryBytes, clientTLSBytes, sessionBytes, g.CreatedAt, g.UpdatedAt,
		); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *Repository) Update(ctx context.Context, g *domain.Gateway) error {
	if g == nil {
		return errors.New("gateway repository: nil gateway")
	}
	telemetryBytes, err := marshalJSON(g.Telemetry)
	if err != nil {
		return fmt.Errorf("gateway repository: marshal telemetry: %w", err)
	}
	clientTLSBytes, err := marshalJSON(g.ClientTLSConfig)
	if err != nil {
		return fmt.Errorf("gateway repository: marshal client_tls: %w", err)
	}
	sessionBytes, err := marshalJSON(g.SessionConfig)
	if err != nil {
		return fmt.Errorf("gateway repository: marshal session_config: %w", err)
	}
	const query = `
		UPDATE gateways
		   SET name           = $2,
		       status         = $3,
		       telemetry      = $4,
		       client_tls     = $5,
		       session_config = $6,
		       updated_at     = $7
		 WHERE id = $1`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query,
			g.ID, g.Name, g.Status, telemetryBytes, clientTLSBytes, sessionBytes, g.UpdatedAt,
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

func (r *Repository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Gateway, error) {
	const query = `
		SELECT id, name, status, telemetry, client_tls, session_config, created_at, updated_at
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
		SELECT id, name, status, telemetry, client_tls, session_config, created_at, updated_at
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

type rowScanner interface {
	Scan(dest ...any) error
}

func scanGateway(s rowScanner) (*domain.Gateway, error) {
	g := &domain.Gateway{}
	var telemetryRaw, clientTLSRaw, sessionRaw []byte
	if err := s.Scan(
		&g.ID, &g.Name, &g.Status,
		&telemetryRaw, &clientTLSRaw, &sessionRaw,
		&g.CreatedAt, &g.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if len(telemetryRaw) > 0 {
		var t telemetry.Telemetry
		if err := json.Unmarshal(telemetryRaw, &t); err != nil {
			return nil, fmt.Errorf("scan telemetry: %w", err)
		}
		g.Telemetry = &t
	}
	if len(clientTLSRaw) > 0 {
		var c domain.ClientTLSConfig
		if err := json.Unmarshal(clientTLSRaw, &c); err != nil {
			return nil, fmt.Errorf("scan client_tls: %w", err)
		}
		g.ClientTLSConfig = c
	}
	if len(sessionRaw) > 0 {
		var sc domain.SessionConfig
		if err := json.Unmarshal(sessionRaw, &sc); err != nil {
			return nil, fmt.Errorf("scan session_config: %w", err)
		}
		g.SessionConfig = &sc
	}

	return g, nil
}

func marshalJSON(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	switch t := v.(type) {
	case *telemetry.Telemetry:
		if t == nil {
			return nil, nil
		}
	case domain.ClientTLSConfig:
		if t == nil {
			return nil, nil
		}
	case *domain.SessionConfig:
		if t == nil {
			return nil, nil
		}
	}
	return json.Marshal(v)
}

func mapPgError(err error) error {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		switch pgErr.Code {
		case pgUniqueViolation:
			return domain.ErrAlreadyExists
		case pgForeignKeyViolation:
			return domain.ErrHasDependents
		}
	}
	return err
}
