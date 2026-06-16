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

package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
	pgCheckViolation      = "23514"
	pgRoutingConflict     = "AG409"

	gatewayFKConstraint          = "consumers_gateway_id_fkey"
	consumerRegistryFKConstraint = "consumer_registry_registry_id_fkey"
	consumerRoleFKConstraint     = "consumer_role_role_id_fkey"
	consumerAuthFKConstraint     = "consumer_auth_auth_id_fkey"
	consumerPolicyFKConstraint   = "consumer_policy_policy_id_fkey"
	consumerSlugUniqueIndex      = "consumers_slug_unique_idx"
	consumerRoutingModeCheck     = "consumers_routing_mode_check"
)

const consumerSelectColumns = `
		SELECT c.id, c.gateway_id, c.name, c.type, c.slug, c.routing_mode, c.lb_config, c.fallback, c.model_policies, c.toolkit, c.fail_mode, c.headers, c.active,
		       c.created_at, c.updated_at,
		       COALESCE((SELECT array_agg(cb.registry_id ORDER BY cb.registry_id)
		                   FROM consumer_registry cb WHERE cb.consumer_id = c.id), '{}')::uuid[] AS registry_ids,
		       COALESCE((SELECT json_object_agg(cw.registry_id, cw.weight)
		                   FROM consumer_registry cw WHERE cw.consumer_id = c.id), '{}')::jsonb AS registry_weights,
		       COALESCE((SELECT array_agg(cr.role_id ORDER BY cr.role_id)
		                   FROM consumer_role cr WHERE cr.consumer_id = c.id), '{}')::uuid[] AS role_ids,
		       COALESCE((SELECT array_agg(ca.auth_id ORDER BY ca.auth_id)
		                   FROM consumer_auth ca WHERE ca.consumer_id = c.id), '{}')::uuid[] AS auth_ids`

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
	headersBytes, err := marshalHeaders(c.Headers)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal headers: %w", err)
	}
	lbConfigBytes, err := marshalLBConfig(c.LBConfig)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal lb_config: %w", err)
	}
	fallbackBytes, err := marshalFallback(c.Fallback)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal fallback: %w", err)
	}
	modelPoliciesBytes, err := marshalModelPolicies(c.ModelPolicies)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal model_policies: %w", err)
	}
	toolkitBytes, err := marshalToolkit(c.Toolkit())
	if err != nil {
		return fmt.Errorf("consumer repository: marshal toolkit: %w", err)
	}
	const insertConsumer = `
		INSERT INTO consumers (
			id, gateway_id, name, type, slug, routing_mode, lb_config, fallback, model_policies, toolkit, fail_mode, headers, active, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)`
	const insertConsumerRegistry = `
		INSERT INTO consumer_registry (consumer_id, registry_id, weight) VALUES ($1, $2, $3)
		ON CONFLICT (consumer_id, registry_id) DO UPDATE SET weight = EXCLUDED.weight`
	const insertConsumerRole = `
		INSERT INTO consumer_role (consumer_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, insertConsumer,
			c.ID, c.GatewayID, c.Name, string(c.Type), c.Slug, string(c.RoutingMode), lbConfigBytes, fallbackBytes, modelPoliciesBytes,
			toolkitBytes, nullableFailMode(c.FailMode()), headersBytes, c.Active, c.CreatedAt, c.UpdatedAt,
		); err != nil {
			return mapPgError(err)
		}
		for _, registryID := range c.RegistryIDs {
			if _, err := tx.Exec(ctx, insertConsumerRegistry, c.ID, registryID, clampRegistryWeight(c.WeightFor(registryID))); err != nil {
				return mapPgError(err)
			}
		}
		for _, roleID := range c.RoleIDs {
			if _, err := tx.Exec(ctx, insertConsumerRole, c.ID, roleID); err != nil {
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
	headersBytes, err := marshalHeaders(c.Headers)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal headers: %w", err)
	}
	lbConfigBytes, err := marshalLBConfig(c.LBConfig)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal lb_config: %w", err)
	}
	fallbackBytes, err := marshalFallback(c.Fallback)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal fallback: %w", err)
	}
	modelPoliciesBytes, err := marshalModelPolicies(c.ModelPolicies)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal model_policies: %w", err)
	}
	toolkitBytes, err := marshalToolkit(c.Toolkit())
	if err != nil {
		return fmt.Errorf("consumer repository: marshal toolkit: %w", err)
	}
	const updateConsumer = `
		UPDATE consumers
		   SET name             = $2,
		       type             = $3,
		       routing_mode     = $4,
		       lb_config        = $5,
		       fallback         = $6,
		       model_policies   = $7,
		       toolkit          = $8,
		       fail_mode        = $9,
		       headers          = $10,
		       active           = $11,
		       updated_at       = $12
		 WHERE id = $1`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if err := lockConsumerRow(ctx, tx, c.ID); err != nil {
			return err
		}
		if err := ensureRegistryRefsAssociated(ctx, tx, c); err != nil {
			return err
		}
		if err := cleanupIncompatibleRelations(ctx, tx, c); err != nil {
			return err
		}
		cmd, err := tx.Exec(ctx, updateConsumer,
			c.ID, c.Name, string(c.Type), string(c.RoutingMode), lbConfigBytes, fallbackBytes, modelPoliciesBytes,
			toolkitBytes, nullableFailMode(c.FailMode()), headersBytes, c.Active, c.UpdatedAt,
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

func cleanupIncompatibleRelations(ctx context.Context, tx pgx.Tx, c *domain.Consumer) error {
	var query string
	switch c.RoutingMode {
	case domain.RoutingModeRoleBased:
		query = `DELETE FROM consumer_registry WHERE consumer_id = $1`
	case domain.RoutingModeInline:
		query = `DELETE FROM consumer_role WHERE consumer_id = $1`
	default:
		return nil
	}
	if _, err := tx.Exec(ctx, query, c.ID); err != nil {
		return mapPgError(err)
	}
	return nil
}

func lockConsumerRow(ctx context.Context, tx pgx.Tx, consumerID ids.ConsumerID) error {
	const query = `SELECT 1 FROM consumers WHERE id = $1 FOR UPDATE`
	var exists int
	if err := tx.QueryRow(ctx, query, consumerID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		return fmt.Errorf("consumer repository: lock consumer: %w", err)
	}
	return nil
}

func ensureRegistryRefsAssociated(ctx context.Context, tx pgx.Tx, c *domain.Consumer) error {
	if c.RoutingMode == domain.RoutingModeRoleBased {
		return nil
	}
	refs := consumerRegistryReferences(c)
	if len(refs) == 0 {
		return nil
	}
	const query = `
		SELECT registry_id
		  FROM consumer_registry
		 WHERE consumer_id = $1
		   AND registry_id = ANY($2::uuid[])`
	rows, err := tx.Query(ctx, query, c.ID, ids.ToUUIDs(refs))
	if err != nil {
		return fmt.Errorf("consumer repository: registry reference check: %w", err)
	}
	defer rows.Close()

	associated := make(map[ids.RegistryID]struct{}, len(refs))
	for rows.Next() {
		var id ids.RegistryID
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("consumer repository: registry reference scan: %w", err)
		}
		associated[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("consumer repository: registry reference iter: %w", err)
	}
	for _, id := range refs {
		if _, ok := associated[id]; !ok {
			return fmt.Errorf("%w: registry %s is not associated with the consumer", registrydomain.ErrInvalidRegistryID, id)
		}
	}
	return nil
}

func (r *Repository) AttachRegistry(ctx context.Context, consumerID ids.ConsumerID, registryID ids.RegistryID, weight *int) error {
	// A nil weight means "attach without changing the weight": a brand-new
	// association defaults to DefaultRegistryWeight, and an existing one keeps the
	// weight it already had so a plain re-attach stays idempotent.
	if weight == nil {
		const query = `
			INSERT INTO consumer_registry (consumer_id, registry_id, weight) VALUES ($1, $2, $3)
			ON CONFLICT (consumer_id, registry_id) DO NOTHING`
		if _, err := r.conn.Pool.Exec(ctx, query, consumerID, registryID, domain.DefaultRegistryWeight); err != nil {
			return mapPgError(err)
		}
		return nil
	}
	const query = `
		INSERT INTO consumer_registry (consumer_id, registry_id, weight) VALUES ($1, $2, $3)
		ON CONFLICT (consumer_id, registry_id) DO UPDATE SET weight = EXCLUDED.weight`
	if _, err := r.conn.Pool.Exec(ctx, query, consumerID, registryID, clampRegistryWeight(*weight)); err != nil {
		return mapPgError(err)
	}
	return nil
}

func clampRegistryWeight(weight int) int {
	if weight < domain.DefaultRegistryWeight {
		return domain.DefaultRegistryWeight
	}
	if weight > domain.MaxRegistryWeight {
		return domain.MaxRegistryWeight
	}
	return weight
}

func (r *Repository) DetachRegistry(ctx context.Context, consumerID ids.ConsumerID, registryID ids.RegistryID) error {
	_, err := r.detachRegistryIfUnreferenced(ctx, ids.GatewayID{}, consumerID, registryID, false)
	return err
}

func (r *Repository) DetachRegistryIfUnreferenced(
	ctx context.Context,
	gatewayID ids.GatewayID,
	consumerID ids.ConsumerID,
	registryID ids.RegistryID,
) (*domain.Consumer, error) {
	return r.detachRegistryIfUnreferenced(ctx, gatewayID, consumerID, registryID, true)
}

func (r *Repository) detachRegistryIfUnreferenced(
	ctx context.Context,
	gatewayID ids.GatewayID,
	consumerID ids.ConsumerID,
	registryID ids.RegistryID,
	checkGateway bool,
) (*domain.Consumer, error) {
	var current *domain.Consumer
	err := database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		consumer, err := lockConsumerRoutingReferences(ctx, tx, consumerID)
		if err != nil {
			return err
		}
		if checkGateway && consumer.GatewayID != gatewayID {
			return domain.ErrNotFound
		}
		if consumerReferencesRegistry(consumer, registryID) {
			return fmt.Errorf("consumer registry %s has dependent routing references: %w", registryID, commonerrors.ErrConflict)
		}
		const query = `DELETE FROM consumer_registry WHERE consumer_id = $1 AND registry_id = $2`
		if _, err := tx.Exec(ctx, query, consumerID, registryID); err != nil {
			return mapPgError(err)
		}
		current = consumer
		return nil
	})
	if err != nil {
		return nil, err
	}
	return current, nil
}

func (r *Repository) AttachRole(ctx context.Context, consumerID ids.ConsumerID, roleID ids.RoleID) error {
	const query = `INSERT INTO consumer_role (consumer_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	if _, err := r.conn.Pool.Exec(ctx, query, consumerID, roleID); err != nil {
		return mapPgError(err)
	}
	return nil
}

func (r *Repository) DetachRole(ctx context.Context, consumerID ids.ConsumerID, roleID ids.RoleID) error {
	const query = `DELETE FROM consumer_role WHERE consumer_id = $1 AND role_id = $2`
	if _, err := r.conn.Pool.Exec(ctx, query, consumerID, roleID); err != nil {
		return mapPgError(err)
	}
	return nil
}

func (r *Repository) AttachAuth(ctx context.Context, consumerID ids.ConsumerID, authID ids.AuthID) error {
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if err := lockConsumerRow(ctx, tx, consumerID); err != nil {
			return err
		}
		var exists bool
		err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auths WHERE id = $1)`, authID).Scan(&exists)
		if err != nil {
			return mapPgError(err)
		}
		if !exists {
			return domain.ErrNotFound
		}
		const query = `INSERT INTO consumer_auth (consumer_id, auth_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
		if _, err := tx.Exec(ctx, query, consumerID, authID); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

func (r *Repository) DetachAuth(ctx context.Context, consumerID ids.ConsumerID, authID ids.AuthID) error {
	const query = `DELETE FROM consumer_auth WHERE consumer_id = $1 AND auth_id = $2`
	if _, err := r.conn.Pool.Exec(ctx, query, consumerID, authID); err != nil {
		return mapPgError(err)
	}
	return nil
}

func (r *Repository) AttachPolicy(ctx context.Context, consumerID ids.ConsumerID, policyID ids.PolicyID) error {
	const query = `INSERT INTO consumer_policy (consumer_id, policy_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	if _, err := r.conn.Pool.Exec(ctx, query, consumerID, policyID); err != nil {
		return mapPgError(err)
	}
	return nil
}

func (r *Repository) DetachPolicy(ctx context.Context, consumerID ids.ConsumerID, policyID ids.PolicyID) error {
	const query = `DELETE FROM consumer_policy WHERE consumer_id = $1 AND policy_id = $2`
	if _, err := r.conn.Pool.Exec(ctx, query, consumerID, policyID); err != nil {
		return mapPgError(err)
	}
	return nil
}

func (r *Repository) Delete(ctx context.Context, id ids.ConsumerID) error {
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

func (r *Repository) FindByID(ctx context.Context, id ids.ConsumerID) (*domain.Consumer, error) {
	query := consumerSelectColumns + `
		  FROM consumers c
		 WHERE c.id = $1`
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

func (r *Repository) FindActiveBySlug(ctx context.Context, slug string) (*domain.Consumer, error) {
	query := consumerSelectColumns + `
		  FROM consumers c
		 WHERE c.slug = $1
		   AND c.active = TRUE`
	row := r.conn.Pool.QueryRow(ctx, query, strings.TrimSpace(slug))
	c, err := scanConsumer(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("consumer repository: find active by slug: %w", err)
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

	gatewayParam := nullableUUID(filter.GatewayID.UUID())

	const countQuery = `
		SELECT COUNT(*)
		  FROM consumers
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%')`
	var total int
	if err := r.conn.Pool.QueryRow(ctx, countQuery, gatewayParam, filter.NameContains).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("consumer repository: count: %w", err)
	}

	listQuery := consumerSelectColumns + `
		  FROM consumers c
		 WHERE ($1::uuid IS NULL OR c.gateway_id = $1)
		   AND ($2 = '' OR lower(c.name) LIKE '%' || lower($2) || '%')
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

func (r *Repository) ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Consumer, error) {
	query := consumerSelectColumns + `
		  FROM consumers c
		 WHERE c.gateway_id = $1
		 ORDER BY c.created_at DESC, c.id`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("consumer repository: list by gateway: %w", err)
	}
	defer rows.Close()

	items := make([]*domain.Consumer, 0)
	for rows.Next() {
		c, err := scanConsumer(rows)
		if err != nil {
			return nil, fmt.Errorf("consumer repository: scan: %w", err)
		}
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("consumer repository: iter: %w", err)
	}
	return items, nil
}

func lockConsumerRoutingReferences(ctx context.Context, tx pgx.Tx, consumerID ids.ConsumerID) (*domain.Consumer, error) {
	const query = `
		SELECT id, gateway_id, fallback, model_policies, lb_config
		  FROM consumers
		 WHERE id = $1
		 FOR UPDATE`
	consumer := &domain.Consumer{}
	var fallbackRaw, modelPoliciesRaw, lbConfigRaw []byte
	if err := tx.QueryRow(ctx, query, consumerID).Scan(
		&consumer.ID,
		&consumer.GatewayID,
		&fallbackRaw,
		&modelPoliciesRaw,
		&lbConfigRaw,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("consumer repository: lock routing references: %w", err)
	}
	if err := hydrateConsumerRoutingReferences(consumer, fallbackRaw, modelPoliciesRaw, lbConfigRaw); err != nil {
		return nil, err
	}
	return consumer, nil
}

func hydrateConsumerRoutingReferences(consumer *domain.Consumer, fallbackRaw, modelPoliciesRaw, lbConfigRaw []byte) error {
	if len(fallbackRaw) > 0 {
		var fallback domain.Fallback
		if err := json.Unmarshal(fallbackRaw, &fallback); err != nil {
			return fmt.Errorf("scan fallback: %w", err)
		}
		consumer.Fallback = &fallback
	}
	if len(modelPoliciesRaw) > 0 {
		var modelPolicies domain.ModelPolicies
		if err := json.Unmarshal(modelPoliciesRaw, &modelPolicies); err != nil {
			return fmt.Errorf("scan model_policies: %w", err)
		}
		consumer.ModelPolicies = modelPolicies
	}
	if len(lbConfigRaw) > 0 {
		var lbConfig domain.LBConfig
		if err := json.Unmarshal(lbConfigRaw, &lbConfig); err != nil {
			return fmt.Errorf("scan lb_config: %w", err)
		}
		consumer.LBConfig = &lbConfig
	}
	return nil
}

func consumerReferencesRegistry(consumer *domain.Consumer, registryID ids.RegistryID) bool {
	if consumer.Fallback != nil {
		for _, id := range consumer.Fallback.Chain {
			if id == registryID {
				return true
			}
		}
	}
	if _, ok := consumer.ModelPolicies[registryID]; ok {
		return true
	}
	if consumer.LBConfig != nil {
		for _, member := range consumer.LBConfig.Members {
			if member.RegistryID == registryID {
				return true
			}
		}
	}
	return false
}

func consumerRegistryReferences(consumer *domain.Consumer) []ids.RegistryID {
	refs := make(map[ids.RegistryID]struct{})
	if consumer.Fallback != nil {
		for _, id := range consumer.Fallback.Chain {
			refs[id] = struct{}{}
		}
	}
	for id := range consumer.ModelPolicies {
		refs[id] = struct{}{}
	}
	if consumer.LBConfig != nil {
		for _, member := range consumer.LBConfig.Members {
			refs[member.RegistryID] = struct{}{}
		}
	}
	out := make([]ids.RegistryID, 0, len(refs))
	for id := range refs {
		out = append(out, id)
	}
	return out
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanConsumer(s rowScanner) (*domain.Consumer, error) {
	c := &domain.Consumer{}
	var (
		headersRaw       []byte
		lbConfigRaw      []byte
		fallbackRaw      []byte
		modelPoliciesRaw []byte
		toolkitRaw       []byte
		failModeRaw      *string
		consumerType     string
		routingMode      string
		registryIDs      []uuid.UUID
		registryWeights  []byte
		roleIDs          []uuid.UUID
		authIDs          []uuid.UUID
	)
	if err := s.Scan(
		&c.ID, &c.GatewayID, &c.Name, &consumerType, &c.Slug, &routingMode, &lbConfigRaw, &fallbackRaw, &modelPoliciesRaw, &toolkitRaw, &failModeRaw, &headersRaw, &c.Active,
		&c.CreatedAt, &c.UpdatedAt,
		&registryIDs, &registryWeights, &roleIDs, &authIDs,
	); err != nil {
		return nil, err
	}
	c.Type = domain.Type(consumerType)
	c.RoutingMode = domain.RoutingMode(routingMode)
	if len(headersRaw) > 0 {
		if err := json.Unmarshal(headersRaw, &c.Headers); err != nil {
			return nil, fmt.Errorf("scan headers: %w", err)
		}
	}
	if len(lbConfigRaw) > 0 {
		var lb domain.LBConfig
		if err := json.Unmarshal(lbConfigRaw, &lb); err != nil {
			return nil, fmt.Errorf("scan lb_config: %w", err)
		}
		c.LBConfig = &lb
	}
	if len(fallbackRaw) > 0 {
		var fb domain.Fallback
		if err := json.Unmarshal(fallbackRaw, &fb); err != nil {
			return nil, fmt.Errorf("scan fallback: %w", err)
		}
		c.Fallback = &fb
	}
	if len(modelPoliciesRaw) > 0 {
		var mp domain.ModelPolicies
		if err := json.Unmarshal(modelPoliciesRaw, &mp); err != nil {
			return nil, fmt.Errorf("scan model_policies: %w", err)
		}
		c.ModelPolicies = mp
	}
	failMode := ""
	if failModeRaw != nil {
		failMode = *failModeRaw
	}
	if len(toolkitRaw) > 0 || failMode != "" {
		mcp := &domain.MCPPolicy{FailMode: domain.FailMode(failMode)}
		if len(toolkitRaw) > 0 {
			if err := json.Unmarshal(toolkitRaw, &mcp.Toolkit); err != nil {
				return nil, fmt.Errorf("scan toolkit: %w", err)
			}
		}
		if len(mcp.Toolkit) > 0 || mcp.FailMode != "" {
			c.MCP = mcp
		}
	}
	c.RegistryIDs = ids.FromUUIDs[ids.RegistryKind](registryIDs)
	c.RoleIDs = ids.FromUUIDs[ids.RoleKind](roleIDs)
	c.AuthIDs = ids.FromUUIDs[ids.AuthKind](authIDs)
	weights, err := parseRegistryWeights(registryWeights)
	if err != nil {
		return nil, err
	}
	c.RegistryWeights = weights
	if c.RegistryIDs == nil {
		c.RegistryIDs = []ids.RegistryID{}
	}
	if c.RoleIDs == nil {
		c.RoleIDs = []ids.RoleID{}
	}
	if c.AuthIDs == nil {
		c.AuthIDs = []ids.AuthID{}
	}
	return c, nil
}

func parseRegistryWeights(raw []byte) (map[ids.RegistryID]int, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	stringKeyed := make(map[string]int)
	if err := json.Unmarshal(raw, &stringKeyed); err != nil {
		return nil, fmt.Errorf("scan registry_weights: %w", err)
	}
	if len(stringKeyed) == 0 {
		return nil, nil
	}
	out := make(map[ids.RegistryID]int, len(stringKeyed))
	for k, v := range stringKeyed {
		id, err := ids.Parse[ids.RegistryKind](k)
		if err != nil {
			return nil, fmt.Errorf("scan registry_weights: invalid registry id %q: %w", k, err)
		}
		out[id] = v
	}
	return out, nil
}

func marshalHeaders(v map[string]string) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(v)
}

func marshalLBConfig(lb *domain.LBConfig) ([]byte, error) {
	if lb == nil {
		return nil, nil
	}
	return json.Marshal(lb)
}

func marshalFallback(f *domain.Fallback) ([]byte, error) {
	if f == nil {
		return nil, nil
	}
	return json.Marshal(f)
}

func marshalModelPolicies(m domain.ModelPolicies) ([]byte, error) {
	if len(m) == 0 {
		return nil, nil
	}
	return json.Marshal(m)
}

func marshalToolkit(t domain.Toolkit) ([]byte, error) {
	if len(t) == 0 {
		return nil, nil
	}
	return json.Marshal(t)
}

func nullableFailMode(fm domain.FailMode) any {
	if fm == "" {
		return nil
	}
	return string(fm)
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
		case pgRoutingConflict:
			return fmt.Errorf("%s: %w", pgErr.Message, commonerrors.ErrConflict)
		case pgUniqueViolation:
			if strings.Contains(pgErr.ConstraintName, consumerSlugUniqueIndex) {
				return domain.ErrSlugAlreadyExists
			}
			return domain.ErrAlreadyExists
		case pgCheckViolation:
			if strings.Contains(pgErr.ConstraintName, consumerRoutingModeCheck) {
				return domain.ErrInvalidRoutingMode
			}
			return err
		case pgForeignKeyViolation:
			if strings.Contains(pgErr.ConstraintName, gatewayFKConstraint) ||
				strings.Contains(pgErr.Detail, "(gateway_id)") {
				return domain.ErrInvalidGatewayID
			}
			if strings.Contains(pgErr.ConstraintName, consumerRegistryFKConstraint) ||
				strings.Contains(pgErr.Detail, "(registry_id)") {
				return registrydomain.ErrInvalidRegistryID
			}
			if strings.Contains(pgErr.ConstraintName, consumerAuthFKConstraint) ||
				strings.Contains(pgErr.Detail, "(auth_id)") {
				return domain.ErrInvalidAuthID
			}
			if strings.Contains(pgErr.ConstraintName, consumerRoleFKConstraint) ||
				strings.Contains(pgErr.Detail, "(role_id)") {
				return roledomain.ErrNotFound
			}
			if strings.Contains(pgErr.ConstraintName, consumerPolicyFKConstraint) ||
				strings.Contains(pgErr.Detail, "(policy_id)") {
				return policydomain.ErrNotFound
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
