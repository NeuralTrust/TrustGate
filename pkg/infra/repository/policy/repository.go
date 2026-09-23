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

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

const policySelectColumns = `
		SELECT p.id, p.gateway_id, p.name, p.slug, p.enabled, p.global, p.priority, p.parallel, p.settings, p.stages, p.created_at, p.updated_at, p.description, p.mode, p.mcp_scope,
		       COALESCE((SELECT array_agg(cp.consumer_id ORDER BY cp.consumer_id)
		                   FROM consumer_policy cp WHERE cp.policy_id = p.id), '{}')::uuid[] AS consumer_ids`

// mcpScopeReferencesRegistry matches policies whose mcp_scope names a registry
// in registry_ids or in tools. The registry id is bound as text because the
// JSONB stores ids as strings; a NULL parameter matches nothing.
const mcpScopeReferencesRegistry = `(mcp_scope->'registry_ids' ? $%[1]d::text
		        OR mcp_scope->'tools' @> jsonb_build_array(jsonb_build_object('registry_id', $%[1]d::text)))`

var _ domain.Repository = (*Repository)(nil)

type Repository struct {
	conn     *database.Connection
	outbox   outbox.Appender
	cipher   vaultdomain.Encrypter
	registry appplugins.Registry
}

// NewRepository builds the pgx policy repository from the shared connection.
// Each write commits its config-snapshot change marker in the same transaction
// via the injected outbox appender.
//
// cipher and registry back the RUN-1646 leaf-level credential encryption
// (see marshalSettings and scanPolicy): registry is how this repository
// learns which dot-separated settings paths a policy's plugin declared as
// credential-bearing (appplugins.CredentialSettings) — the repository has
// only the policy's slug, not the plugin's shape. Depending on
// appplugins.Registry here (an app-layer interface) rather than duplicating
// that lookup mirrors the existing pkg/infra/repository/gatewaystate ->
// pkg/app/gateway precedent, and does not create an import cycle: the plugin
// registry's own dependencies (adapters, embeddings, cache, config) never
// reach back into pkg/infra/repository (verified via `go list -deps`).
// Either may be nil (functional tests that do not exercise credential
// plugins, or a caller that genuinely has neither); a nil registry makes
// PluginCredentialPaths return no paths, and a nil cipher is checked
// explicitly, so settings pass through exactly as before — the same
// unaffected-by-default posture CredentialSettings already has everywhere
// else.
func NewRepository(conn *database.Connection, appender outbox.Appender, cipher vaultdomain.Encrypter, registry appplugins.Registry) *Repository {
	return &Repository{conn: conn, outbox: appender, cipher: cipher, registry: registry}
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

func (r *Repository) Save(ctx context.Context, p *domain.Policy) error {
	if p == nil {
		return errors.New("policy repository: nil policy")
	}
	settingsBytes, err := r.marshalSettings(p.Slug, p.Settings)
	if err != nil {
		return fmt.Errorf("policy repository: marshal settings: %w", err)
	}
	stagesBytes, err := marshalStages(p.Stages)
	if err != nil {
		return fmt.Errorf("policy repository: marshal stages: %w", err)
	}
	scopeBytes, err := marshalMCPScope(p.MCPScope)
	if err != nil {
		return fmt.Errorf("policy repository: marshal mcp_scope: %w", err)
	}
	const query = `
		INSERT INTO policies (id, gateway_id, name, slug, enabled, global, priority, parallel, settings, stages, created_at, updated_at, description, mode, mcp_scope)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query,
			p.ID, p.GatewayID, p.Name, p.Slug, p.Enabled, p.Global, p.Priority, p.Parallel,
			settingsBytes, stagesBytes, p.CreatedAt, p.UpdatedAt, p.Description, string(p.Mode.Normalize()), scopeBytes,
		); err != nil {
			return mapPgError(err)
		}
		return nil
	})
}

// Update writes every column of p. writeMCPScope false leaves mcp_scope as
// stored, so an update that did not ask to change the scope cannot overwrite a
// prune that ran between the caller's read and this write.
func (r *Repository) Update(ctx context.Context, p *domain.Policy, writeMCPScope bool) error {
	if p == nil {
		return errors.New("policy repository: nil policy")
	}
	settingsBytes, err := r.marshalSettings(p.Slug, p.Settings)
	if err != nil {
		return fmt.Errorf("policy repository: marshal settings: %w", err)
	}
	stagesBytes, err := marshalStages(p.Stages)
	if err != nil {
		return fmt.Errorf("policy repository: marshal stages: %w", err)
	}
	scopeBytes, err := marshalMCPScope(p.MCPScope)
	if err != nil {
		return fmt.Errorf("policy repository: marshal mcp_scope: %w", err)
	}
	const query = `
		UPDATE policies
		   SET name        = $2,
		       slug        = $3,
		       enabled     = $4,
		       global      = $5,
		       priority    = $6,
		       parallel    = $7,
		       settings    = $8,
		       stages      = $9,
		       updated_at  = $10,
		       description = $11,
		       mode        = $12,
		       mcp_scope   = CASE WHEN $15::boolean THEN $14::jsonb ELSE mcp_scope END
		 WHERE id = $1 AND gateway_id = $13`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query,
			p.ID, p.Name, p.Slug, p.Enabled, p.Global, p.Priority, p.Parallel,
			settingsBytes, stagesBytes, p.UpdatedAt, p.Description, string(p.Mode.Normalize()), p.GatewayID, scopeBytes,
			writeMCPScope,
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

func (r *Repository) SetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID, global bool) error {
	const query = `UPDATE policies SET global = $2, updated_at = now() WHERE id = $1 AND gateway_id = $3`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, query, id, global, gatewayID)
		if err != nil {
			return mapPgError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *Repository) Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) error {
	const query = `DELETE FROM policies WHERE id = $1 AND gateway_id = $2`
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

func (r *Repository) FindByID(ctx context.Context, id ids.PolicyID) (*domain.Policy, error) {
	query := policySelectColumns + `
		  FROM policies p
		 WHERE p.id = $1`
	row := r.conn.Pool.QueryRow(ctx, query, id)
	p, err := r.scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("policy repository: find: %w", err)
	}
	return p, nil
}

func (r *Repository) FindByIDs(ctx context.Context, gatewayID ids.GatewayID, policyIDs []ids.PolicyID) ([]*domain.Policy, error) {
	if len(policyIDs) == 0 {
		return nil, nil
	}
	query := policySelectColumns + `
		  FROM policies p
		 WHERE p.gateway_id = $1
		   AND p.id = ANY($2::uuid[])`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID.UUID(), ids.ToUUIDs(policyIDs))
	if err != nil {
		return nil, fmt.Errorf("policy repository: find by ids: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Policy, 0, len(policyIDs))
	for rows.Next() {
		p, err := r.scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("policy repository: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policy repository: iter: %w", err)
	}
	return out, nil
}

func (r *Repository) ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Policy, error) {
	query := policySelectColumns + `
		  FROM policies p
		 WHERE p.gateway_id = $1
		 ORDER BY p.priority, p.created_at, p.id`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID.UUID())
	if err != nil {
		return nil, fmt.Errorf("policy repository: list by gateway: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Policy, 0)
	for rows.Next() {
		p, err := r.scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("policy repository: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policy repository: iter: %w", err)
	}
	return out, nil
}

func (r *Repository) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Policy, int, error) {
	page := filter.Page.Normalize()
	offset := page.Offset()

	countQuery := `
		SELECT COUNT(*)
		  FROM policies
		 WHERE ($1::uuid IS NULL OR gateway_id = $1)
		   AND ($2 = '' OR lower(name) LIKE '%' || lower($2) || '%' OR lower(slug) LIKE '%' || lower($2) || '%')
		   AND ($3::boolean IS NULL OR enabled = $3)
		   AND ($4::boolean IS NULL OR global = $4)
		   AND ($5 = '' OR mode = $5)
		   AND (NOT $6::boolean OR slug = ANY($7::text[]))
		   AND ($8::text IS NULL OR ` + fmt.Sprintf(mcpScopeReferencesRegistry, 8) + `)`

	gatewayParam := nullableUUID(filter.GatewayID.UUID())
	modeParam := string(filter.Mode)
	slugs := filter.Slugs
	if slugs == nil {
		slugs = []string{}
	}
	registryParam := nullableRegistryID(filter.RegistryID)

	var total int
	if err := r.conn.Pool.QueryRow(
		ctx,
		countQuery,
		gatewayParam,
		filter.Search,
		filter.Enabled,
		filter.Global,
		modeParam,
		filter.RestrictToSlugs,
		slugs,
		registryParam,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("policy repository: count: %w", err)
	}

	listQuery := policySelectColumns + `
		  FROM policies p
		 WHERE ($1::uuid IS NULL OR p.gateway_id = $1)
		   AND ($2 = '' OR lower(p.name) LIKE '%' || lower($2) || '%' OR lower(p.slug) LIKE '%' || lower($2) || '%')
		   AND ($3::boolean IS NULL OR p.enabled = $3)
		   AND ($4::boolean IS NULL OR p.global = $4)
		   AND ($5 = '' OR p.mode = $5)
		   AND (NOT $6::boolean OR p.slug = ANY($7::text[]))
		   AND ($8::text IS NULL OR ` + fmt.Sprintf(mcpScopeReferencesRegistry, 8) + `)
		 ORDER BY ` + policyOrderBy(filter.Sort) + `
		 LIMIT $9 OFFSET $10`
	rows, err := r.conn.Pool.Query(
		ctx,
		listQuery,
		gatewayParam,
		filter.Search,
		filter.Enabled,
		filter.Global,
		modeParam,
		filter.RestrictToSlugs,
		slugs,
		registryParam,
		page.Size,
		offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("policy repository: list: %w", err)
	}
	defer rows.Close()

	items := make([]*domain.Policy, 0, page.Size)
	for rows.Next() {
		p, err := r.scanPolicy(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("policy repository: scan: %w", err)
		}
		items = append(items, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("policy repository: iter: %w", err)
	}
	return items, total, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

// scanPolicy is a method (not a free function) because decrypting settings
// needs r.registry to resolve the policy's declared credential paths from its
// slug, and r.cipher to decrypt them.
func (r *Repository) scanPolicy(s rowScanner) (*domain.Policy, error) {
	p := &domain.Policy{}
	var settingsRaw []byte
	var stagesRaw []byte
	var scopeRaw []byte
	var consumerIDs []uuid.UUID
	var mode string
	if err := s.Scan(
		&p.ID, &p.GatewayID, &p.Name, &p.Slug, &p.Enabled, &p.Global, &p.Priority, &p.Parallel,
		&settingsRaw, &stagesRaw,
		&p.CreatedAt, &p.UpdatedAt, &p.Description, &mode, &scopeRaw,
		&consumerIDs,
	); err != nil {
		return nil, err
	}
	p.Mode = domain.Mode(mode).Normalize()
	p.ConsumerIDs = ids.FromUUIDs[ids.ConsumerKind](consumerIDs)

	if len(settingsRaw) > 0 {
		if err := json.Unmarshal(settingsRaw, &p.Settings); err != nil {
			return nil, fmt.Errorf("scan settings: %w", err)
		}
		if err := r.decryptSettingsInPlace(p); err != nil {
			return nil, err
		}
	}
	if len(stagesRaw) > 0 {
		if err := json.Unmarshal(stagesRaw, &p.Stages); err != nil {
			return nil, fmt.Errorf("scan stages: %w", err)
		}
	}
	scope, err := unmarshalMCPScope(scopeRaw)
	if err != nil {
		return nil, err
	}
	p.MCPScope = scope
	return p, nil
}

// marshalMCPScope keeps the nil-vs-empty distinction on the wire: a nil scope
// becomes SQL NULL and an empty one becomes '{}', which matches nothing.
func marshalMCPScope(s *domain.MCPScope) ([]byte, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

func unmarshalMCPScope(raw []byte) (*domain.MCPScope, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	scope := &domain.MCPScope{}
	if err := json.Unmarshal(raw, scope); err != nil {
		return nil, fmt.Errorf("scan mcp_scope: %w", err)
	}
	return scope, nil
}

// marshalSettings encrypts every settings leaf slug's plugin declared as
// credential-bearing (appplugins.CredentialSettings) before marshalling.
// Only those declared leaves are touched — settings stays JSONB with every
// other key readable and migratable in plain SQL (see
// 20260902120000_trustguard_direction_only.go, which rewrites keys inside
// this same column with jsonb operators; whole-blob encryption would make
// that kind of migration permanently impossible). It never mutates s: s is
// frequently the same map the caller also hands to plugin execution (see
// app/plugins/plan.go), which needs the real credential.
func (r *Repository) marshalSettings(slug string, s map[string]any) ([]byte, error) {
	if len(s) == 0 {
		return []byte("{}"), nil
	}
	if paths := appplugins.PluginCredentialPaths(r.registry, slug); len(paths) > 0 && r.cipher != nil {
		encrypted, err := secret.EncryptSettings(s, paths, r.cipher)
		if err != nil {
			return nil, fmt.Errorf("encrypt settings: %w", err)
		}
		s = encrypted
	}
	return json.Marshal(s)
}

// decryptSettingsInPlace is the tolerant read RUN-1646 requires: it decrypts
// only the settings leaves p.Slug's plugin declared as credential-bearing,
// and only the ones that actually carry secret.EncVersionPrefix. A leaf
// without the prefix is legacy plaintext (written before this feature
// existed, or before the backfill reached that row) and is left exactly as
// found — never attempted, never an error.
//
// A leaf that does carry the prefix but fails to decrypt (wrong
// SERVER_SECRET_KEY after an unplanned rotation, or corrupted data) is
// returned as a wrapped commonerrors.ErrCorruptData, the same convention
// pkg/infra/repository/registry already uses for its own encrypted column.
// Every caller of scanPolicy (FindByID, FindByIDs, ListByGateway, List) is
// already in the row-loop-aborts-on-any-error shape that convention implies;
// that is the pre-existing blast radius tracked as RUN-1662/RUN-1663, not
// something this change introduces. What this change guarantees is that the
// realistic universe of rows able to hit that path — genuinely corrupted or
// mis-keyed ciphertext — is exactly the rows that carry the version prefix;
// every legacy plaintext row, which is every row before the backfill
// finishes, never reaches Decrypt at all.
func (r *Repository) decryptSettingsInPlace(p *domain.Policy) error {
	paths := appplugins.PluginCredentialPaths(r.registry, p.Slug)
	if len(paths) == 0 || r.cipher == nil {
		return nil
	}
	decrypted, err := secret.DecryptSettings(p.Settings, paths, r.cipher)
	if err != nil {
		return fmt.Errorf("decrypt settings: %w: %w", commonerrors.ErrCorruptData, err)
	}
	p.Settings = decrypted
	return nil
}

func marshalStages(stages []domain.Stage) ([]byte, error) {
	if len(stages) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(stages)
}

func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func nullableRegistryID(id *ids.RegistryID) any {
	if id == nil || id.IsNil() {
		return nil
	}
	return id.String()
}

func policyOrderBy(sort listing.Sort) string {
	col := "p.created_at"
	dir := listing.Desc
	if !sort.IsZero() {
		switch sort.Field {
		case "name":
			col = "p.name"
		case "created_at":
			col = "p.created_at"
		case "updated_at":
			col = "p.updated_at"
		case "priority":
			col = "p.priority"
		}
		dir = sort.Direction
		if dir == "" {
			dir = listing.Asc
		}
	}
	return col + " " + dir.SQL() + ", p.id"
}

func mapPgError(err error) error {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		switch pgErr.Code {
		case pgUniqueViolation:
			return domain.ErrAlreadyExists
		case pgForeignKeyViolation:
			if strings.Contains(pgErr.ConstraintName, "consumer_id") ||
				strings.Contains(pgErr.Detail, "(consumer_id)") {
				return domain.ErrInvalidConsumerID
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
