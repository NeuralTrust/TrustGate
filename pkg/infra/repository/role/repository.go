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

package role

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
	pgCrossGatewayLink    = "AG422"

	roleGatewayFKConstraint        = "roles_gateway_id_fkey"
	roleRegistryRegistryConstraint = "role_registry_registry_id_fkey"
	roleRegistryRoleIDFKConstraint = "role_registry_role_id_fkey"
)

const roleSelectColumns = `
		SELECT r.id, r.gateway_id, r.name, r.model_policies, r.mcp_policies, r.oidc_mapping, r.created_at, r.updated_at,
		       COALESCE((SELECT array_agg(rr.registry_id ORDER BY rr.registry_id)
		                   FROM role_registry rr WHERE rr.role_id = r.id), '{}')::uuid[] AS registry_ids`

var _ domain.Repository = (*Repository)(nil)

type Repository struct {
	conn   *database.Connection
	outbox outbox.Appender
}

// NewRepository builds the pgx role repository from the shared connection.
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

func (r *Repository) Save(ctx context.Context, role *domain.Role) error {
	if role == nil {
		return errors.New("role repository: nil role")
	}
	modelPoliciesBytes, err := marshalModelPolicies(role.ModelPolicies)
	if err != nil {
		return fmt.Errorf("role repository: marshal model_policies: %w", err)
	}
	mcpPoliciesBytes, err := marshalMCPPolicies(role.MCPPolicies)
	if err != nil {
		return fmt.Errorf("role repository: marshal mcp_policies: %w", err)
	}
	const query = `
		INSERT INTO roles (id, gateway_id, name, model_policies, mcp_policies, oidc_mapping, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query,
			role.ID, role.GatewayID, role.Name, modelPoliciesBytes, nullableJSON(mcpPoliciesBytes), nullableJSON(role.OIDCMapping),
			role.CreatedAt, role.UpdatedAt,
		); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *Repository) Update(ctx context.Context, role *domain.Role) error {
	if role == nil {
		return errors.New("role repository: nil role")
	}
	modelPoliciesBytes, err := marshalModelPolicies(role.ModelPolicies)
	if err != nil {
		return fmt.Errorf("role repository: marshal model_policies: %w", err)
	}
	mcpPoliciesBytes, err := marshalMCPPolicies(role.MCPPolicies)
	if err != nil {
		return fmt.Errorf("role repository: marshal mcp_policies: %w", err)
	}
	const query = `
		UPDATE roles
		   SET name           = $2,
		       model_policies = $3,
		       mcp_policies   = $4,
		       oidc_mapping    = $5,
		       updated_at     = $6
		 WHERE id = $1 AND gateway_id = $7`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if err := lockRoleRow(ctx, tx, role.ID); err != nil {
			return err
		}
		if err := ensureRoleRegistryRefsAssociated(ctx, tx, role); err != nil {
			return err
		}
		cmd, err := tx.Exec(ctx, query,
			role.ID, role.Name, modelPoliciesBytes, nullableJSON(mcpPoliciesBytes), nullableJSON(role.OIDCMapping), role.UpdatedAt, role.GatewayID,
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

func lockRoleRow(ctx context.Context, tx pgx.Tx, roleID ids.RoleID) error {
	const query = `SELECT 1 FROM roles WHERE id = $1 FOR UPDATE`
	var exists int
	if err := tx.QueryRow(ctx, query, roleID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		return fmt.Errorf("role repository: lock role: %w", err)
	}
	return nil
}

func ensureRoleRegistryRefsAssociated(ctx context.Context, tx pgx.Tx, role *domain.Role) error {
	refs := roleRegistryReferences(role)
	if len(refs) == 0 {
		return nil
	}
	const query = `
		SELECT registry_id
		  FROM role_registry
		 WHERE role_id = $1
		   AND registry_id = ANY($2::uuid[])`
	rows, err := tx.Query(ctx, query, role.ID, ids.ToUUIDs(refs))
	if err != nil {
		return fmt.Errorf("role repository: registry reference check: %w", err)
	}
	defer rows.Close()

	associated := make(map[ids.RegistryID]struct{}, len(refs))
	for rows.Next() {
		var id ids.RegistryID
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("role repository: registry reference scan: %w", err)
		}
		associated[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("role repository: registry reference iter: %w", err)
	}
	for _, id := range refs {
		if _, ok := associated[id]; !ok {
			return fmt.Errorf("%w: registry %s is not bound to role", domain.ErrInvalidModelPolicy, id)
		}
	}
	return nil
}

func (r *Repository) Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.RoleID) error {
	const query = `DELETE FROM roles WHERE id = $1 AND gateway_id = $2`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query, id, gatewayID)
		if err != nil {
			return mapPgDeleteError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *Repository) FindByID(ctx context.Context, id ids.RoleID) (*domain.Role, error) {
	query := roleSelectColumns + `
		  FROM roles r
		 WHERE r.id = $1`
	row := r.conn.Pool.QueryRow(ctx, query, id)
	role, err := scanRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("role repository: find: %w", err)
	}
	return role, nil
}

func (r *Repository) FindByIDs(ctx context.Context, gatewayID ids.GatewayID, roleIDs []ids.RoleID) ([]*domain.Role, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	query := roleSelectColumns + `
		  FROM roles r
		 WHERE r.gateway_id = $1
		   AND r.id = ANY($2::uuid[])`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID.UUID(), ids.ToUUIDs(roleIDs))
	if err != nil {
		return nil, fmt.Errorf("role repository: find by ids: %w", err)
	}
	defer rows.Close()
	out := make([]*domain.Role, 0, len(roleIDs))
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, fmt.Errorf("role repository: scan: %w", err)
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("role repository: iter: %w", err)
	}
	return out, nil
}

func (r *Repository) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Role, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Size < 1 {
		filter.Size = 20
	}
	offset := (filter.Page - 1) * filter.Size
	gatewayParam := nullableUUID(filter.GatewayID.UUID())
	const countQuery = `
		SELECT COUNT(*)
		  FROM roles
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%')`
	var total int
	if err := r.conn.Pool.QueryRow(ctx, countQuery, gatewayParam, filter.NameContains).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("role repository: count: %w", err)
	}
	listQuery := roleSelectColumns + `
		  FROM roles r
		 WHERE ($1::uuid IS NULL OR r.gateway_id = $1)
		   AND ($2 = '' OR lower(r.name) LIKE '%' || lower($2) || '%')
		 ORDER BY r.created_at DESC, r.id
		 LIMIT $3 OFFSET $4`
	rows, err := r.conn.Pool.Query(ctx, listQuery, gatewayParam, filter.NameContains, filter.Size, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("role repository: list: %w", err)
	}
	defer rows.Close()
	items := make([]*domain.Role, 0, filter.Size)
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("role repository: scan: %w", err)
		}
		items = append(items, role)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("role repository: iter: %w", err)
	}
	return items, total, nil
}

func (r *Repository) ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Role, error) {
	query := roleSelectColumns + `
		  FROM roles r
		 WHERE r.gateway_id = $1
		 ORDER BY r.created_at DESC, r.id`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("role repository: list by gateway: %w", err)
	}
	defer rows.Close()
	items := make([]*domain.Role, 0)
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, fmt.Errorf("role repository: scan: %w", err)
		}
		items = append(items, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("role repository: iter: %w", err)
	}
	return items, nil
}

func (r *Repository) AttachRegistry(ctx context.Context, roleID ids.RoleID, registryID ids.RegistryID) error {
	const query = `INSERT INTO role_registry (role_id, registry_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, roleID, registryID); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *Repository) DetachRegistry(ctx context.Context, roleID ids.RoleID, registryID ids.RegistryID) error {
	_, err := r.detachRegistryIfUnreferenced(ctx, ids.GatewayID{}, roleID, registryID, false)
	return err
}

func (r *Repository) DetachRegistryIfUnreferenced(
	ctx context.Context,
	gatewayID ids.GatewayID,
	roleID ids.RoleID,
	registryID ids.RegistryID,
) (*domain.Role, error) {
	return r.detachRegistryIfUnreferenced(ctx, gatewayID, roleID, registryID, true)
}

func (r *Repository) detachRegistryIfUnreferenced(
	ctx context.Context,
	gatewayID ids.GatewayID,
	roleID ids.RoleID,
	registryID ids.RegistryID,
	checkGateway bool,
) (*domain.Role, error) {
	var current *domain.Role
	err := r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		role, err := lockRolePolicies(ctx, tx, roleID)
		if err != nil {
			return err
		}
		if checkGateway && role.GatewayID != gatewayID {
			return domain.ErrNotFound
		}
		if roleReferencesRegistry(role, registryID) {
			return fmt.Errorf("role registry %s has dependent policy references: %w", registryID, commonerrors.ErrConflict)
		}
		const query = `DELETE FROM role_registry WHERE role_id = $1 AND registry_id = $2`
		if _, err := tx.Exec(ctx, query, roleID, registryID); err != nil {
			return mapPgError(err)
		}
		current = role
		return nil
	})
	if err != nil {
		return nil, err
	}
	return current, nil
}

func lockRolePolicies(ctx context.Context, tx pgx.Tx, roleID ids.RoleID) (*domain.Role, error) {
	const query = `
		SELECT id, gateway_id, model_policies, mcp_policies
		  FROM roles
		 WHERE id = $1
		 FOR UPDATE`
	role := &domain.Role{}
	var modelPoliciesRaw, mcpPoliciesRaw []byte
	if err := tx.QueryRow(ctx, query, roleID).Scan(&role.ID, &role.GatewayID, &modelPoliciesRaw, &mcpPoliciesRaw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("role repository: lock policies: %w", err)
	}
	if len(modelPoliciesRaw) > 0 {
		var modelPolicies domain.ModelPolicies
		if err := json.Unmarshal(modelPoliciesRaw, &modelPolicies); err != nil {
			return nil, fmt.Errorf("scan model_policies: %w", err)
		}
		role.ModelPolicies = modelPolicies
	}
	mcpPolicies, err := decodeMCPPolicies(mcpPoliciesRaw)
	if err != nil {
		return nil, err
	}
	role.MCPPolicies = mcpPolicies
	return role, nil
}

func decodeMCPPolicies(raw []byte) (*domain.MCPPolicies, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var policies domain.MCPPolicies
	if err := json.Unmarshal(raw, &policies); err != nil {
		return nil, fmt.Errorf("scan mcp_policies: %w", err)
	}
	return &policies, nil
}

func roleReferencesRegistry(role *domain.Role, registryID ids.RegistryID) bool {
	if _, ok := role.ModelPolicies[registryID]; ok {
		return true
	}
	if role.MCPPolicies == nil {
		return false
	}
	for _, entry := range role.MCPPolicies.Toolkit {
		if entry.RegistryID == registryID {
			return true
		}
	}
	return false
}

func roleRegistryReferences(role *domain.Role) []ids.RegistryID {
	seen := make(map[ids.RegistryID]struct{}, len(role.ModelPolicies))
	refs := make([]ids.RegistryID, 0, len(role.ModelPolicies))
	for id := range role.ModelPolicies {
		seen[id] = struct{}{}
		refs = append(refs, id)
	}
	if role.MCPPolicies != nil {
		for _, entry := range role.MCPPolicies.Toolkit {
			if _, dup := seen[entry.RegistryID]; dup {
				continue
			}
			seen[entry.RegistryID] = struct{}{}
			refs = append(refs, entry.RegistryID)
		}
	}
	return refs
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRole(s rowScanner) (*domain.Role, error) {
	role := &domain.Role{}
	var (
		modelPoliciesRaw []byte
		mcpPoliciesRaw   []byte
		idpMappingRaw    []byte
		registryIDs      []uuid.UUID
	)
	if err := s.Scan(
		&role.ID, &role.GatewayID, &role.Name, &modelPoliciesRaw, &mcpPoliciesRaw, &idpMappingRaw,
		&role.CreatedAt, &role.UpdatedAt, &registryIDs,
	); err != nil {
		return nil, err
	}
	if len(modelPoliciesRaw) > 0 {
		var policies domain.ModelPolicies
		if err := json.Unmarshal(modelPoliciesRaw, &policies); err != nil {
			return nil, fmt.Errorf("scan model_policies: %w", err)
		}
		role.ModelPolicies = policies
	}
	mcpPolicies, err := decodeMCPPolicies(mcpPoliciesRaw)
	if err != nil {
		return nil, err
	}
	role.MCPPolicies = mcpPolicies
	role.OIDCMapping = idpMappingRaw
	role.RegistryIDs = ids.FromUUIDs[ids.RegistryKind](registryIDs)
	if role.RegistryIDs == nil {
		role.RegistryIDs = []ids.RegistryID{}
	}
	return role, nil
}

func marshalModelPolicies(m domain.ModelPolicies) ([]byte, error) {
	if len(m) == 0 {
		return nil, nil
	}
	return json.Marshal(m)
}

func marshalMCPPolicies(p *domain.MCPPolicies) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	return json.Marshal(p)
}

func nullableJSON(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
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
		case pgCrossGatewayLink:
			return fmt.Errorf("%s: %w", pgErr.Message, commonerrors.ErrConflict)
		case pgUniqueViolation:
			return domain.ErrAlreadyExists
		case pgForeignKeyViolation:
			if strings.Contains(pgErr.ConstraintName, roleGatewayFKConstraint) ||
				strings.Contains(pgErr.Detail, "(gateway_id)") {
				return domain.ErrInvalidGatewayID
			}
			if strings.Contains(pgErr.ConstraintName, roleRegistryRegistryConstraint) ||
				strings.Contains(pgErr.Detail, "(registry_id)") {
				return registrydomain.ErrInvalidRegistryID
			}
			if strings.Contains(pgErr.ConstraintName, roleRegistryRoleIDFKConstraint) ||
				strings.Contains(pgErr.Detail, "(role_id)") {
				return domain.ErrNotFound
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
