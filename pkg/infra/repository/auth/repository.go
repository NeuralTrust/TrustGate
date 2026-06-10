package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
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

func (r *Repository) Save(ctx context.Context, a *domain.Auth) error {
	if a == nil {
		return errors.New("auth repository: nil auth")
	}
	configBytes, err := json.Marshal(a.Config)
	if err != nil {
		return fmt.Errorf("auth repository: marshal config: %w", err)
	}
	const query = `
		INSERT INTO auths (id, gateway_id, name, type, enabled, config, key_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query,
			a.ID, a.GatewayID, a.Name, string(a.Type), a.Enabled, configBytes, nullableString(a.KeyHash), a.CreatedAt, a.UpdatedAt,
		); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *Repository) Update(ctx context.Context, a *domain.Auth) error {
	if a == nil {
		return errors.New("auth repository: nil auth")
	}
	configBytes, err := json.Marshal(a.Config)
	if err != nil {
		return fmt.Errorf("auth repository: marshal config: %w", err)
	}
	const query = `
		UPDATE auths
		   SET name       = $2,
		       type       = $3,
		       enabled    = $4,
		       config     = $5,
		       key_hash   = $6,
		       updated_at = $7
		 WHERE id = $1`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query, a.ID, a.Name, string(a.Type), a.Enabled, configBytes, nullableString(a.KeyHash), a.UpdatedAt)
		if err != nil {
			return mapPgError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *Repository) Delete(ctx context.Context, id ids.AuthID) error {
	const query = `DELETE FROM auths WHERE id = $1`
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

func (r *Repository) FindByID(ctx context.Context, id ids.AuthID) (*domain.Auth, error) {
	const query = `
		SELECT id, gateway_id, name, type, enabled, config, key_hash, created_at, updated_at
		  FROM auths
		 WHERE id = $1`
	row := r.conn.Pool.QueryRow(ctx, query, id)
	a, err := scanAuth(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("auth repository: find: %w", err)
	}
	return a, nil
}

func (r *Repository) FindByAPIKeyHash(ctx context.Context, keyHash string) (*domain.Auth, error) {
	const query = `
		SELECT id, gateway_id, name, type, enabled, config, key_hash, created_at, updated_at
		  FROM auths
		 WHERE key_hash = $1
		   AND type = 'api_key'
		   AND enabled = TRUE`
	row := r.conn.Pool.QueryRow(ctx, query, keyHash)
	a, err := scanAuth(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("auth repository: find by api key hash: %w", err)
	}
	return a, nil
}

func (r *Repository) FindByIDs(ctx context.Context, gatewayID ids.GatewayID, authIDs []ids.AuthID) ([]*domain.Auth, error) {
	if len(authIDs) == 0 {
		return nil, nil
	}
	const query = `
		SELECT id, gateway_id, name, type, enabled, config, key_hash, created_at, updated_at
		  FROM auths
		 WHERE gateway_id = $1
		   AND id = ANY($2::uuid[])`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID.UUID(), ids.ToUUIDs(authIDs))
	if err != nil {
		return nil, fmt.Errorf("auth repository: find by ids: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Auth, 0, len(authIDs))
	for rows.Next() {
		a, err := scanAuth(rows)
		if err != nil {
			return nil, fmt.Errorf("auth repository: scan: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth repository: iter: %w", err)
	}
	return out, nil
}

func (r *Repository) ListEnabledByGatewayAndType(
	ctx context.Context,
	gatewayID ids.GatewayID,
	authType domain.Type,
) ([]*domain.Auth, error) {
	const query = `
		SELECT id, gateway_id, name, type, enabled, config, key_hash, created_at, updated_at
		  FROM auths
		 WHERE gateway_id = $1
		   AND type = $2
		   AND enabled = TRUE
		 ORDER BY created_at DESC, id`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID, string(authType))
	if err != nil {
		return nil, fmt.Errorf("auth repository: list enabled by gateway and type: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Auth, 0)
	for rows.Next() {
		a, err := scanAuth(rows)
		if err != nil {
			return nil, fmt.Errorf("auth repository: scan: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth repository: iter: %w", err)
	}
	return out, nil
}

func (r *Repository) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Auth, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Size < 1 {
		filter.Size = 20
	}
	offset := (filter.Page - 1) * filter.Size

	const countQuery = `
		SELECT COUNT(*)
		  FROM auths
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%')`

	gatewayParam := nullableUUID(filter.GatewayID.UUID())

	var total int
	if err := r.conn.Pool.QueryRow(ctx, countQuery, gatewayParam, filter.NameContains).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("auth repository: count: %w", err)
	}

	const listQuery = `
		SELECT id, gateway_id, name, type, enabled, config, key_hash, created_at, updated_at
		  FROM auths
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%')
		 ORDER BY created_at DESC, id
		 LIMIT $3 OFFSET $4`
	rows, err := r.conn.Pool.Query(ctx, listQuery, gatewayParam, filter.NameContains, filter.Size, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("auth repository: list: %w", err)
	}
	defer rows.Close()

	items := make([]*domain.Auth, 0, filter.Size)
	for rows.Next() {
		a, err := scanAuth(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("auth repository: scan: %w", err)
		}
		items = append(items, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("auth repository: iter: %w", err)
	}
	return items, total, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAuth(s rowScanner) (*domain.Auth, error) {
	a := &domain.Auth{}
	var (
		authType  string
		configRaw []byte
		keyHash   *string
	)
	if err := s.Scan(
		&a.ID, &a.GatewayID, &a.Name, &authType, &a.Enabled,
		&configRaw, &keyHash,
		&a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return nil, err
	}
	a.Type = domain.Type(authType)
	if keyHash != nil {
		a.KeyHash = *keyHash
	}
	if len(configRaw) > 0 {
		if err := json.Unmarshal(configRaw, &a.Config); err != nil {
			return nil, fmt.Errorf("scan config: %w", err)
		}
	}
	return a, nil
}

func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
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
