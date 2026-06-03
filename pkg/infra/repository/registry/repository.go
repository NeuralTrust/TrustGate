package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
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

func (r *Repository) Save(ctx context.Context, b *domain.Registry) error {
	if b == nil {
		return errors.New("registry repository: nil registry")
	}
	providerOptionsBytes, err := marshalProviderOptions(b.ProviderOptions)
	if err != nil {
		return fmt.Errorf("registry repository: marshal provider_options: %w", err)
	}
	authBytes, err := marshalAuth(b.Auth)
	if err != nil {
		return fmt.Errorf("registry repository: marshal auth: %w", err)
	}
	healthChecksBytes, err := marshalHealthChecks(b.HealthChecks)
	if err != nil {
		return fmt.Errorf("registry repository: marshal health_checks: %w", err)
	}
	const query = `
		INSERT INTO registries (id, gateway_id, name, provider, provider_options, auth, weight, description, health_checks, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query,
			b.ID, b.GatewayID, b.Name, b.Provider, providerOptionsBytes, authBytes, b.Weight, b.Description, healthChecksBytes, b.CreatedAt, b.UpdatedAt,
		); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *Repository) Update(ctx context.Context, b *domain.Registry) error {
	if b == nil {
		return errors.New("registry repository: nil registry")
	}
	providerOptionsBytes, err := marshalProviderOptions(b.ProviderOptions)
	if err != nil {
		return fmt.Errorf("registry repository: marshal provider_options: %w", err)
	}
	authBytes, err := marshalAuth(b.Auth)
	if err != nil {
		return fmt.Errorf("registry repository: marshal auth: %w", err)
	}
	healthChecksBytes, err := marshalHealthChecks(b.HealthChecks)
	if err != nil {
		return fmt.Errorf("registry repository: marshal health_checks: %w", err)
	}
	const query = `
		UPDATE registries
		   SET name             = $2,
		       provider         = $3,
		       provider_options = $4,
		       auth             = $5,
		       weight           = $6,
		       description      = $7,
		       health_checks    = $8,
		       updated_at       = $9
		 WHERE id = $1`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query,
			b.ID, b.Name, b.Provider, providerOptionsBytes, authBytes, b.Weight, b.Description, healthChecksBytes, b.UpdatedAt,
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

func (r *Repository) Delete(ctx context.Context, id ids.RegistryID) error {
	const query = `DELETE FROM registries WHERE id = $1`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {

		if err := ensureNotInFallbackChain(ctx, tx, id); err != nil {
			return err
		}
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

func ensureNotInFallbackChain(ctx context.Context, tx pgx.Tx, id ids.RegistryID) error {
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM consumers
			 WHERE fallback IS NOT NULL
			   AND fallback->'chain' @> to_jsonb($1::text)
		)`
	var referenced bool
	if err := tx.QueryRow(ctx, query, id.String()).Scan(&referenced); err != nil {
		return fmt.Errorf("registry repository: fallback-chain check: %w", err)
	}
	if referenced {
		return domain.ErrHasDependents
	}
	return nil
}

func (r *Repository) FindByID(ctx context.Context, id ids.RegistryID) (*domain.Registry, error) {
	const query = `
		SELECT id, gateway_id, name, provider, provider_options, auth, weight, description, health_checks, created_at, updated_at
		  FROM registries
		 WHERE id = $1`
	row := r.conn.Pool.QueryRow(ctx, query, id)
	b, err := scanRegistry(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("registry repository: find: %w", err)
	}
	return b, nil
}

func (r *Repository) FindByIDs(ctx context.Context, gatewayID ids.GatewayID, registryIDs []ids.RegistryID) ([]*domain.Registry, error) {
	if len(registryIDs) == 0 {
		return nil, nil
	}
	const query = `
		SELECT id, gateway_id, name, provider, provider_options, auth, weight, description, health_checks, created_at, updated_at
		  FROM registries
		 WHERE gateway_id = $1
		   AND id = ANY($2::uuid[])`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID.UUID(), ids.ToUUIDs(registryIDs))
	if err != nil {
		return nil, fmt.Errorf("registry repository: find by ids: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Registry, 0, len(registryIDs))
	for rows.Next() {
		b, err := scanRegistry(rows)
		if err != nil {
			return nil, fmt.Errorf("registry repository: scan: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("registry repository: iter: %w", err)
	}
	return out, nil
}

func (r *Repository) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Registry, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Size < 1 {
		filter.Size = 20
	}
	offset := (filter.Page - 1) * filter.Size

	const countQuery = `
		SELECT COUNT(*)
		  FROM registries
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%')`

	gatewayParam := nullableUUID(filter.GatewayID.UUID())

	var total int
	if err := r.conn.Pool.QueryRow(ctx, countQuery, gatewayParam, filter.NameContains).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("registry repository: count: %w", err)
	}

	const listQuery = `
		SELECT id, gateway_id, name, provider, provider_options, auth, weight, description, health_checks, created_at, updated_at
		  FROM registries
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%')
		 ORDER BY created_at DESC, id
		 LIMIT $3 OFFSET $4`
	rows, err := r.conn.Pool.Query(ctx, listQuery, gatewayParam, filter.NameContains, filter.Size, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("registry repository: list: %w", err)
	}
	defer rows.Close()

	items := make([]*domain.Registry, 0, filter.Size)
	for rows.Next() {
		b, err := scanRegistry(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("registry repository: scan: %w", err)
		}
		items = append(items, b)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("registry repository: iter: %w", err)
	}
	return items, total, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRegistry(s rowScanner) (*domain.Registry, error) {
	b := &domain.Registry{}
	var providerOptionsRaw, authRaw, healthChecksRaw []byte
	if err := s.Scan(
		&b.ID, &b.GatewayID, &b.Name, &b.Provider,
		&providerOptionsRaw, &authRaw, &b.Weight, &b.Description, &healthChecksRaw,
		&b.CreatedAt, &b.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if len(providerOptionsRaw) > 0 {
		if err := json.Unmarshal(providerOptionsRaw, &b.ProviderOptions); err != nil {
			return nil, fmt.Errorf("scan provider_options: %w", err)
		}
	}

	if len(authRaw) > 0 {
		var auth domain.TargetAuth
		if err := json.Unmarshal(authRaw, &auth); err != nil {
			return nil, fmt.Errorf("scan auth: %w", err)
		}
		b.Auth = &auth
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

func marshalProviderOptions(o map[string]any) ([]byte, error) {
	if len(o) == 0 {
		return nil, nil
	}
	return json.Marshal(o)
}

func marshalAuth(a *domain.TargetAuth) ([]byte, error) {
	if a == nil {
		return nil, nil
	}
	return json.Marshal(a)
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
