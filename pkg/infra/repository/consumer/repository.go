package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"

	gatewayFKConstraint          = "consumers_gateway_id_fkey"
	consumerRegistryFKConstraint = "consumer_registry_registry_id_fkey"
	consumerAuthFKConstraint     = "consumer_auth_auth_id_fkey"
	consumerPolicyFKConstraint   = "consumer_policy_policy_id_fkey"
	consumerPathUniqueIndex      = "consumers_gateway_path_unique"
)

const consumerSelectColumns = `
		SELECT c.id, c.gateway_id, c.name, c.type, c.path, c.algorithm, c.embedding_config, c.fallback, c.model_policies, c.toolkit, c.fail_mode, c.headers, c.active,
		       c.created_at, c.updated_at,
		       COALESCE((SELECT array_agg(cb.registry_id ORDER BY cb.registry_id)
		                   FROM consumer_registry cb WHERE cb.consumer_id = c.id), '{}')::uuid[] AS registry_ids,
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
	embeddingBytes, err := marshalEmbedding(c.EmbeddingConfig())
	if err != nil {
		return fmt.Errorf("consumer repository: marshal embedding_config: %w", err)
	}
	fallbackBytes, err := marshalFallback(c.Fallback())
	if err != nil {
		return fmt.Errorf("consumer repository: marshal fallback: %w", err)
	}
	modelPoliciesBytes, err := marshalModelPolicies(c.ModelPolicies())
	if err != nil {
		return fmt.Errorf("consumer repository: marshal model_policies: %w", err)
	}
	toolkitBytes, err := marshalToolkit(c.Toolkit())
	if err != nil {
		return fmt.Errorf("consumer repository: marshal toolkit: %w", err)
	}
	const insertConsumer = `
		INSERT INTO consumers (
			id, gateway_id, name, type, path, algorithm, embedding_config, fallback, model_policies, toolkit, fail_mode, headers, active, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)`
	if _, err := r.conn.Pool.Exec(ctx, insertConsumer,
		c.ID, c.GatewayID, c.Name, string(c.Type), c.Path, c.Algorithm(), embeddingBytes, fallbackBytes, modelPoliciesBytes,
		toolkitBytes, failMode(c), headersBytes, c.Active, c.CreatedAt, c.UpdatedAt,
	); err != nil {
		return mapPgError(err)
	}
	return nil
}

func (r *Repository) Update(ctx context.Context, c *domain.Consumer) error {
	if c == nil {
		return errors.New("consumer repository: nil consumer")
	}
	headersBytes, err := marshalHeaders(c.Headers)
	if err != nil {
		return fmt.Errorf("consumer repository: marshal headers: %w", err)
	}
	embeddingBytes, err := marshalEmbedding(c.EmbeddingConfig())
	if err != nil {
		return fmt.Errorf("consumer repository: marshal embedding_config: %w", err)
	}
	fallbackBytes, err := marshalFallback(c.Fallback())
	if err != nil {
		return fmt.Errorf("consumer repository: marshal fallback: %w", err)
	}
	modelPoliciesBytes, err := marshalModelPolicies(c.ModelPolicies())
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
		       path             = $4,
		       algorithm        = $5,
		       embedding_config = $6,
		       fallback         = $7,
		       model_policies   = $8,
		       toolkit          = $9,
		       fail_mode        = $10,
		       headers          = $11,
		       active           = $12,
		       updated_at       = $13
		 WHERE id = $1`
	cmd, err := r.conn.Pool.Exec(ctx, updateConsumer,
		c.ID, c.Name, string(c.Type), c.Path, c.Algorithm(), embeddingBytes, fallbackBytes, modelPoliciesBytes,
		toolkitBytes, failMode(c), headersBytes, c.Active, c.UpdatedAt,
	)
	if err != nil {
		return mapPgError(err)
	}
	if cmd.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *Repository) AttachRegistry(ctx context.Context, consumerID ids.ConsumerID, registryID ids.RegistryID) error {
	const query = `INSERT INTO consumer_registry (consumer_id, registry_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	if _, err := r.conn.Pool.Exec(ctx, query, consumerID, registryID); err != nil {
		return mapPgError(err)
	}
	return nil
}

func (r *Repository) DetachRegistry(ctx context.Context, consumerID ids.ConsumerID, registryID ids.RegistryID) error {
	const query = `DELETE FROM consumer_registry WHERE consumer_id = $1 AND registry_id = $2`
	if _, err := r.conn.Pool.Exec(ctx, query, consumerID, registryID); err != nil {
		return mapPgError(err)
	}
	return nil
}

func (r *Repository) AttachAuth(ctx context.Context, consumerID ids.ConsumerID, authID ids.AuthID) error {
	const query = `INSERT INTO consumer_auth (consumer_id, auth_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	if _, err := r.conn.Pool.Exec(ctx, query, consumerID, authID); err != nil {
		return mapPgError(err)
	}
	return nil
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

func (r *Repository) FindActiveByPath(ctx context.Context, path string) ([]*domain.Consumer, error) {
	query := consumerSelectColumns + `
		  FROM consumers c
		 WHERE c.active AND (c.path = $1 OR c.path = $1 || '/')
		 ORDER BY c.created_at ASC, c.id`
	rows, err := r.conn.Pool.Query(ctx, query, path)
	if err != nil {
		return nil, fmt.Errorf("consumer repository: find active by path: %w", err)
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

type rowScanner interface {
	Scan(dest ...any) error
}

func scanConsumer(s rowScanner) (*domain.Consumer, error) {
	c := &domain.Consumer{}
	var (
		headersRaw       []byte
		embeddingRaw     []byte
		fallbackRaw      []byte
		modelPoliciesRaw []byte
		toolkitRaw       []byte
		algorithmRaw     string
		failModeRaw      string
		consumerType     string
		registryIDs      []uuid.UUID
		authIDs          []uuid.UUID
	)
	if err := s.Scan(
		&c.ID, &c.GatewayID, &c.Name, &consumerType, &c.Path, &algorithmRaw, &embeddingRaw, &fallbackRaw, &modelPoliciesRaw, &toolkitRaw, &failModeRaw, &headersRaw, &c.Active,
		&c.CreatedAt, &c.UpdatedAt,
		&registryIDs, &authIDs,
	); err != nil {
		return nil, err
	}
	c.Type = domain.Type(consumerType)
	if c.Type == "" {
		c.Type = domain.TypeLLM
	}
	if len(headersRaw) > 0 {
		if err := json.Unmarshal(headersRaw, &c.Headers); err != nil {
			return nil, fmt.Errorf("scan headers: %w", err)
		}
	}
	switch c.Type {
	case domain.TypeLLM:
		llm := &domain.LLMPolicy{Algorithm: algorithmRaw}
		if len(embeddingRaw) > 0 {
			var ec registrydomain.EmbeddingConfig
			if err := json.Unmarshal(embeddingRaw, &ec); err != nil {
				return nil, fmt.Errorf("scan embedding_config: %w", err)
			}
			llm.EmbeddingConfig = &ec
		}
		if len(fallbackRaw) > 0 {
			var fb domain.Fallback
			if err := json.Unmarshal(fallbackRaw, &fb); err != nil {
				return nil, fmt.Errorf("scan fallback: %w", err)
			}
			llm.Fallback = &fb
		}
		if len(modelPoliciesRaw) > 0 {
			var mp domain.ModelPolicies
			if err := json.Unmarshal(modelPoliciesRaw, &mp); err != nil {
				return nil, fmt.Errorf("scan model_policies: %w", err)
			}
			llm.ModelPolicies = mp
		}
		c.LLM = llm
	case domain.TypeMCP:
		mcp := &domain.MCPPolicy{FailMode: domain.FailMode(failModeRaw)}
		if mcp.FailMode == "" {
			mcp.FailMode = domain.FailModeClosed
		}
		if len(toolkitRaw) > 0 {
			var tk domain.Toolkit
			if err := json.Unmarshal(toolkitRaw, &tk); err != nil {
				return nil, fmt.Errorf("scan toolkit: %w", err)
			}
			mcp.Toolkit = tk
		}
		c.MCP = mcp
	}
	c.RegistryIDs = registrydomain.Registries(ids.FromUUIDs[ids.RegistryKind](registryIDs))
	c.AuthIDs = ids.FromUUIDs[ids.AuthKind](authIDs)
	if c.RegistryIDs == nil {
		c.RegistryIDs = registrydomain.Registries{}
	}
	if c.AuthIDs == nil {
		c.AuthIDs = []ids.AuthID{}
	}
	return c, nil
}

func marshalHeaders(v map[string]string) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(v)
}

func marshalEmbedding(e *registrydomain.EmbeddingConfig) ([]byte, error) {
	if e == nil {
		return nil, nil
	}
	return json.Marshal(e)
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

func failMode(c *domain.Consumer) string {
	if c.FailMode() == "" {
		return string(domain.FailModeClosed)
	}
	return string(c.FailMode())
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
			if strings.Contains(pgErr.ConstraintName, consumerPathUniqueIndex) {
				return domain.ErrPathAlreadyExists
			}
			return domain.ErrAlreadyExists
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
