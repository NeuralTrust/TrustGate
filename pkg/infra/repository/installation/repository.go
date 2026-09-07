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

package installation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const pgForeignKeyViolation = "23503"

const selectColumns = `
	SELECT id, gateway_id, principal_sub, catalog_code, status, installed_by, config, registry_id,
	       decision, decided_by, decided_at, created_at, updated_at
	  FROM store_installations`

var _ domain.Repository = (*Repository)(nil)

// Repository is the pgx-backed store-installation repository. Installations are
// per-principal state that lives outside the config-snapshot, so writes do not
// append an outbox marker (unlike consumers / auths / roles).
type Repository struct {
	conn *database.Connection
}

func NewRepository(conn *database.Connection) *Repository {
	return &Repository{conn: conn}
}

func (r *Repository) Upsert(ctx context.Context, in *domain.Installation) error {
	if in == nil {
		return errors.New("installation repository: nil installation")
	}
	configJSON, err := marshalConfig(in.Config)
	if err != nil {
		return fmt.Errorf("installation repository: marshal config: %w", err)
	}
	// Keyed by id: a principal may hold several instances of one catalog code, so
	// the old (gateway, principal, code) conflict target no longer identifies a
	// row. A fresh install mints a new id (a new instance); re-touching an
	// existing instance carries its id and updates in place.
	// The decision columns are only ever written by the approver; a write that
	// carries no decision (a data-plane install touching its row) keeps the one
	// already recorded rather than blanking the history.
	const query = `
		INSERT INTO store_installations
			(id, gateway_id, principal_sub, catalog_code, status, installed_by, config, registry_id,
			 decision, decided_by, decided_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO UPDATE
			SET status       = EXCLUDED.status,
			    installed_by = EXCLUDED.installed_by,
			    config       = EXCLUDED.config,
			    registry_id  = EXCLUDED.registry_id,
			    decision     = CASE WHEN EXCLUDED.decision <> '' THEN EXCLUDED.decision ELSE store_installations.decision END,
			    decided_by   = CASE WHEN EXCLUDED.decision <> '' THEN EXCLUDED.decided_by ELSE store_installations.decided_by END,
			    decided_at   = CASE WHEN EXCLUDED.decision <> '' THEN EXCLUDED.decided_at ELSE store_installations.decided_at END,
			    updated_at   = EXCLUDED.updated_at`
	if _, err := r.conn.Pool.Exec(ctx, query,
		in.ID, in.GatewayID, in.PrincipalSub, in.CatalogCode, string(in.Status),
		in.InstalledBy, configJSON, nullableRegistryID(in.RegistryID),
		string(in.Decision), in.DecidedBy, nullableTime(in.DecidedAt), in.CreatedAt, in.UpdatedAt,
	); err != nil {
		return mapPgError(err)
	}
	return nil
}

func (r *Repository) Find(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, catalogCode string,
) (*domain.Installation, error) {
	// Several instances of one code may exist. Prefer an ACTIVE (installed) row,
	// then the earliest, deterministically: single-instance readers (dial-time
	// config resolver, admin reads) must never pick a revoked or pending row over
	// a live one.
	const query = selectColumns + `
		WHERE gateway_id = $1 AND principal_sub = $2 AND catalog_code = $3
		ORDER BY (status = $4) DESC, created_at, id
		LIMIT 1`
	row := r.conn.Pool.QueryRow(ctx, query, gatewayID, principalSub, catalogCode, string(domain.StatusInstalled))
	in, err := scanInstallation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return in, nil
}

func (r *Repository) FindByID(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	id ids.InstallationID,
) (*domain.Installation, error) {
	const query = selectColumns + `
		WHERE gateway_id = $1 AND principal_sub = $2 AND id = $3`
	row := r.conn.Pool.QueryRow(ctx, query, gatewayID, principalSub, id)
	in, err := scanInstallation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return in, nil
}

func (r *Repository) ListByPrincipalAndCode(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, catalogCode string,
) ([]*domain.Installation, error) {
	const query = selectColumns + `
		WHERE gateway_id = $1 AND principal_sub = $2 AND catalog_code = $3
		ORDER BY created_at, id`
	return r.queryList(ctx, query, gatewayID, principalSub, catalogCode)
}

func (r *Repository) ListByPrincipal(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
) ([]*domain.Installation, error) {
	const query = selectColumns + `
		WHERE gateway_id = $1 AND principal_sub = $2
		ORDER BY catalog_code`
	return r.queryList(ctx, query, gatewayID, principalSub)
}

func (r *Repository) ListByCatalogCode(
	ctx context.Context,
	gatewayID ids.GatewayID,
	catalogCode string,
) ([]*domain.Installation, error) {
	const query = selectColumns + `
		WHERE gateway_id = $1 AND catalog_code = $2
		ORDER BY principal_sub`
	return r.queryList(ctx, query, gatewayID, catalogCode)
}

func (r *Repository) ListPendingByGateway(
	ctx context.Context,
	gatewayID ids.GatewayID,
) ([]*domain.Installation, error) {
	const query = selectColumns + `
		WHERE gateway_id = $1 AND status = $2
		ORDER BY created_at`
	return r.queryList(ctx, query, gatewayID, string(domain.StatusPendingApproval))
}

// ListDecidedByGateway returns the requests an admin has decided on a gateway,
// newest decision first — the approval queue's History view.
func (r *Repository) ListDecidedByGateway(
	ctx context.Context,
	gatewayID ids.GatewayID,
	limit int,
) ([]*domain.Installation, error) {
	if limit <= 0 {
		limit = 200
	}
	const query = selectColumns + `
		WHERE gateway_id = $1 AND decision <> ''
		ORDER BY decided_at DESC NULLS LAST, updated_at DESC
		LIMIT $2`
	return r.queryList(ctx, query, gatewayID, limit)
}

var _ domain.DecisionHistory = (*Repository)(nil)

func (r *Repository) Delete(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, catalogCode string,
) error {
	const query = `
		DELETE FROM store_installations
		WHERE gateway_id = $1 AND principal_sub = $2 AND catalog_code = $3`
	tag, err := r.conn.Pool.Exec(ctx, query, gatewayID, principalSub, catalogCode)
	if err != nil {
		return mapPgError(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// DeleteByID revokes one instance in place (status = revoked) rather than
// deleting the row: the row is retained for audit, IsActive() drops it from the
// Store surface, and a later re-install of the same config reactivates it. This
// mirrors the data-plane client's implementation exactly, so an uninstall
// behaves identically whichever plane serves it. Delete (by code) stays a hard
// delete for clearing inactive leftovers.
func (r *Repository) DeleteByID(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	id ids.InstallationID,
) error {
	const query = `
		UPDATE store_installations
		   SET status = $4, updated_at = $5
		 WHERE gateway_id = $1 AND principal_sub = $2 AND id = $3`
	tag, err := r.conn.Pool.Exec(ctx, query, gatewayID, principalSub, id,
		string(domain.StatusRevoked), time.Now().UTC())
	if err != nil {
		return mapPgError(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *Repository) queryList(ctx context.Context, query string, args ...any) ([]*domain.Installation, error) {
	rows, err := r.conn.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()
	out := make([]*domain.Installation, 0)
	for rows.Next() {
		in, err := scanInstallation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanInstallation(row scannable) (*domain.Installation, error) {
	var (
		in         domain.Installation
		status     string
		decision   string
		decidedAt  *time.Time
		configJSON []byte
		registryID *ids.RegistryID
	)
	if err := row.Scan(
		&in.ID, &in.GatewayID, &in.PrincipalSub, &in.CatalogCode, &status,
		&in.InstalledBy, &configJSON, &registryID,
		&decision, &in.DecidedBy, &decidedAt, &in.CreatedAt, &in.UpdatedAt,
	); err != nil {
		return nil, err
	}
	in.Status = domain.Status(status)
	in.Decision = domain.Decision(decision)
	if decidedAt != nil {
		in.DecidedAt = *decidedAt
	}
	if registryID != nil {
		in.RegistryID = *registryID
	}
	config, err := unmarshalConfig(configJSON)
	if err != nil {
		return nil, fmt.Errorf("installation repository: unmarshal config: %w", err)
	}
	in.Config = config
	return &in, nil
}

// nullableTime stores the zero time as SQL NULL.
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// nullableRegistryID stores the nil id as SQL NULL ("the code's canonical
// instance") so the column reads naturally in admin queries.
func nullableRegistryID(id ids.RegistryID) *ids.RegistryID {
	if id.IsNil() {
		return nil
	}
	return &id
}

func marshalConfig(config map[string]string) ([]byte, error) {
	if len(config) == 0 {
		return nil, nil
	}
	return json.Marshal(config)
}

func unmarshalConfig(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var config map[string]string
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, err
	}
	return config, nil
}

func mapPgError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation {
		return fmt.Errorf("%w: unknown gateway", domain.ErrInvalidInstallation)
	}
	return fmt.Errorf("installation repository: %w", err)
}
