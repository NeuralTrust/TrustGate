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

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"

	gatewaySlugUniqueConstraint = "gateways_slug_unique_idx"
)

var _ domain.Repository = (*Repository)(nil)

type Repository struct {
	conn   *database.Connection
	outbox outbox.Appender
}

// NewRepository builds the pgx gateway repository from the shared connection.
// Each write commits its config-snapshot change marker in the same transaction
// via the injected outbox appender.
func NewRepository(conn *database.Connection, appender outbox.Appender) *Repository {
	return &Repository{conn: conn, outbox: appender}
}

// withMarkedTx runs fn inside a transaction and, when it succeeds, appends one
// config-snapshot change marker so the mutation and its marker commit atomically.
func (r *Repository) withMarkedTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return r.outbox.AppendTx(ctx, tx)
	})
}

func (r *Repository) Save(ctx context.Context, g *domain.Gateway) error {
	if g == nil {
		return errors.New("gateway repository: nil gateway")
	}
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		return insertGatewayTx(ctx, tx, g)
	})
}

// SaveWithTenantCap serializes the count-then-insert behind a tenant-keyed Postgres advisory lock so concurrent creates can't both pass the cap check.
func (r *Repository) SaveWithTenantCap(ctx context.Context, g *domain.Gateway, tenantID string, maxInstances int) error {
	if g == nil {
		return errors.New("gateway repository: nil gateway")
	}
	if tenantID == "" || maxInstances <= 0 {
		return r.Save(ctx, g)
	}
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenantID); err != nil {
			return fmt.Errorf("gateway repository: acquire tenant lock: %w", err)
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM gateways WHERE metadata->>'tenant_id' = $1`, tenantID).Scan(&count); err != nil {
			return fmt.Errorf("gateway repository: count by tenant: %w", err)
		}
		if count >= maxInstances {
			return ratelimit.ErrInstanceLimit
		}
		return insertGatewayTx(ctx, tx, g)
	})
}

func insertGatewayTx(ctx context.Context, tx pgx.Tx, g *domain.Gateway) error {
	metadataBytes, err := marshalJSON(g.Metadata)
	if err != nil {
		return fmt.Errorf("gateway repository: marshal metadata: %w", err)
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
	entitlementsBytes, err := marshalJSON(g.Entitlements)
	if err != nil {
		return fmt.Errorf("gateway repository: marshal entitlements: %w", err)
	}
	const query = `
		INSERT INTO gateways (id, slug, status, domain, metadata, telemetry, client_tls, session_config, entitlements, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	if _, err := tx.Exec(ctx, query,
		g.ID, g.Slug, g.Status, g.Domain, metadataBytes, telemetryBytes, clientTLSBytes, sessionBytes, entitlementsBytes, g.CreatedAt, g.UpdatedAt,
	); err != nil {
		return mapPgError(err)
	}
	return nil
}

func (r *Repository) Update(ctx context.Context, g *domain.Gateway) error {
	if g == nil {
		return errors.New("gateway repository: nil gateway")
	}
	metadataBytes, err := marshalJSON(g.Metadata)
	if err != nil {
		return fmt.Errorf("gateway repository: marshal metadata: %w", err)
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
	entitlementsBytes, err := marshalJSON(g.Entitlements)
	if err != nil {
		return fmt.Errorf("gateway repository: marshal entitlements: %w", err)
	}
	const query = `
		UPDATE gateways
		   SET slug           = $2,
		       status         = $3,
		       domain         = $4,
		       metadata       = $5,
		       telemetry      = $6,
		       client_tls     = $7,
		       session_config = $8,
		       entitlements   = $9,
		       updated_at     = $10
		 WHERE id = $1`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query,
			g.ID, g.Slug, g.Status, g.Domain, metadataBytes, telemetryBytes, clientTLSBytes, sessionBytes, entitlementsBytes, g.UpdatedAt,
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

// cascadeDeleteStatements removes every resource that belongs to the gateway
// before the gateway row itself. The order respects the ON DELETE RESTRICT
// foreign keys on the junction tables (consumer_auth.auth_id,
// consumer_policy.policy_id, role_registry.registry_id, consumer_registry.registry_id):
// consumers and roles are deleted first so their junction rows cascade away,
// leaving auths, policies and registries free to be removed.
var cascadeDeleteStatements = []string{
	`DELETE FROM consumers  WHERE gateway_id = $1`,
	`DELETE FROM roles      WHERE gateway_id = $1`,
	`DELETE FROM policies   WHERE gateway_id = $1`,
	`DELETE FROM auths      WHERE gateway_id = $1`,
	`DELETE FROM registries WHERE gateway_id = $1`,
}

func (r *Repository) Delete(ctx context.Context, id ids.GatewayID) error {
	const deleteGateway = `DELETE FROM gateways WHERE id = $1`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		for _, stmt := range cascadeDeleteStatements {
			if _, err := tx.Exec(ctx, stmt, id); err != nil {
				return mapPgError(err)
			}
		}
		cmd, err := tx.Exec(ctx, deleteGateway, id)
		if err != nil {
			return mapPgError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *Repository) FindByID(ctx context.Context, id ids.GatewayID) (*domain.Gateway, error) {
	const query = `
		SELECT id, slug, status, domain, metadata, telemetry, client_tls, session_config, entitlements, created_at, updated_at
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

func (r *Repository) FindByDomain(ctx context.Context, host string) (*domain.Gateway, error) {
	const query = `
		SELECT id, slug, status, domain, metadata, telemetry, client_tls, session_config, entitlements, created_at, updated_at
		  FROM gateways
		 WHERE domain = $1 AND domain <> ''`
	row := r.conn.Pool.QueryRow(ctx, query, host)
	g, err := scanGateway(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("gateway repository: find by domain: %w", err)
	}
	return g, nil
}

func (r *Repository) FindBySlug(ctx context.Context, slug string) (*domain.Gateway, error) {
	const query = `
		SELECT id, slug, status, domain, metadata, telemetry, client_tls, session_config, entitlements, created_at, updated_at
		  FROM gateways
		 WHERE slug = $1`
	row := r.conn.Pool.QueryRow(ctx, query, domain.NormalizeSlug(slug))
	g, err := scanGateway(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("gateway repository: find by slug: %w", err)
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
		 WHERE ($1 = '' OR lower(slug) LIKE '%' || lower($1) || '%')`
	var total int
	if err := r.conn.Pool.QueryRow(ctx, countQuery, filter.SlugContains).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("gateway repository: count: %w", err)
	}

	const listQuery = `
		SELECT id, slug, status, domain, metadata, telemetry, client_tls, session_config, entitlements, created_at, updated_at
		  FROM gateways
		 WHERE ($1 = '' OR lower(slug) LIKE '%' || lower($1) || '%')
		 ORDER BY created_at DESC, id
		 LIMIT $2 OFFSET $3`
	rows, err := r.conn.Pool.Query(ctx, listQuery, filter.SlugContains, filter.Size, offset)
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

func (r *Repository) CountByTenantID(ctx context.Context, tenantID string) (int, error) {
	const query = `SELECT COUNT(*) FROM gateways WHERE metadata->>'tenant_id' = $1`
	var count int
	if err := r.conn.Pool.QueryRow(ctx, query, tenantID).Scan(&count); err != nil {
		return 0, fmt.Errorf("gateway repository: count by tenant: %w", err)
	}
	return count, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanGateway(s rowScanner) (*domain.Gateway, error) {
	g := &domain.Gateway{}
	var metadataRaw, telemetryRaw, clientTLSRaw, sessionRaw, entitlementsRaw []byte
	if err := s.Scan(
		&g.ID, &g.Slug, &g.Status, &g.Domain,
		&metadataRaw, &telemetryRaw, &clientTLSRaw, &sessionRaw, &entitlementsRaw,
		&g.CreatedAt, &g.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if len(metadataRaw) > 0 {
		var m map[string]string
		if err := json.Unmarshal(metadataRaw, &m); err != nil {
			return nil, fmt.Errorf("scan metadata: %w", err)
		}
		g.Metadata = m
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
	g.Entitlements = domain.DefaultEntitlements()
	if len(entitlementsRaw) > 0 {
		var e domain.Entitlements
		if err := json.Unmarshal(entitlementsRaw, &e); err != nil {
			return nil, fmt.Errorf("scan entitlements: %w", err)
		}
		g.Entitlements = e
	}

	return g, nil
}

func marshalJSON(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	switch t := v.(type) {
	case map[string]string:
		if t == nil {
			return nil, nil
		}
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
			if strings.Contains(pgErr.ConstraintName, gatewaySlugUniqueConstraint) {
				return fmt.Errorf("%w: the slug is already taken", domain.ErrAlreadyExists)
			}
			return domain.ErrAlreadyExists
		case pgForeignKeyViolation:
			return domain.ErrHasDependents
		}
	}
	return err
}
