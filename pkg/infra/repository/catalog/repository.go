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

package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/jackc/pgx/v5"
)

var _ domain.Repository = (*Repository)(nil)

type Repository struct {
	conn   *database.Connection
	outbox outbox.Appender
}

// NewRepository builds the pgx catalog repository from the shared connection.
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

func (r *Repository) UpsertProvider(ctx context.Context, p *domain.Provider) error {
	metadata, err := marshalJSONB(p.Metadata)
	if err != nil {
		return fmt.Errorf("catalog repository: marshal provider metadata: %w", err)
	}
	const query = `
		INSERT INTO providers_catalog (id, code, display_name, wire_format, source, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
		ON CONFLICT (code) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			wire_format  = EXCLUDED.wire_format,
			source       = EXCLUDED.source,
			metadata     = EXCLUDED.metadata,
			updated_at   = EXCLUDED.updated_at`
	now := time.Now().UTC()
	id := p.ID
	if id.IsNil() {
		id = ids.New[ids.ProviderKind]()
	}
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query, id, p.Code, p.DisplayName, p.WireFormat, p.Source, metadata, now)
		return err
	})
}

func (r *Repository) UpsertModel(ctx context.Context, m *domain.Model) error {
	capabilities, err := marshalJSONB(m.Capabilities)
	if err != nil {
		return fmt.Errorf("catalog repository: marshal model capabilities: %w", err)
	}
	const query = `
		INSERT INTO models_catalog (
			id, provider_id, slug, external_id, display_name, context_window, max_output,
			input_price, output_price, cache_read_price, cache_write_price, capabilities, enabled, source, release_date,
			input_modalities, output_modalities, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $18)
		ON CONFLICT (provider_id, slug) DO UPDATE SET
			external_id       = EXCLUDED.external_id,
			display_name      = EXCLUDED.display_name,
			context_window    = EXCLUDED.context_window,
			max_output        = EXCLUDED.max_output,
			input_price       = EXCLUDED.input_price,
			output_price      = EXCLUDED.output_price,
			cache_read_price  = EXCLUDED.cache_read_price,
			cache_write_price = EXCLUDED.cache_write_price,
			capabilities      = EXCLUDED.capabilities,
			enabled           = EXCLUDED.enabled,
			source            = EXCLUDED.source,
			release_date      = EXCLUDED.release_date,
			input_modalities  = EXCLUDED.input_modalities,
			output_modalities = EXCLUDED.output_modalities,
			updated_at        = EXCLUDED.updated_at`
	now := time.Now().UTC()
	id := m.ID
	if id.IsNil() {
		id = ids.New[ids.ModelKind]()
	}
	// The modality columns are NOT NULL DEFAULT '{}', so coalesce nil slices to
	// empty arrays — pgx encodes a nil slice as SQL NULL, which the column rejects.
	inputModalities := m.InputModalities
	if inputModalities == nil {
		inputModalities = []string{}
	}
	outputModalities := m.OutputModalities
	if outputModalities == nil {
		outputModalities = []string{}
	}
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query,
			id, m.ProviderID, m.Slug, m.ExternalID, m.DisplayName, m.ContextWindow, m.MaxOutput,
			m.InputPrice, m.OutputPrice, m.CacheReadPrice, m.CacheWritePrice,
			capabilities, m.Enabled, m.Source, m.ReleaseDate,
			inputModalities, outputModalities, now,
		)
		return err
	})
}

func (r *Repository) DisableModelsExcept(ctx context.Context, providerID ids.ProviderID, source string, keepSlugs []string) error {
	if keepSlugs == nil {
		keepSlugs = []string{}
	}
	const query = `
		UPDATE models_catalog
		   SET enabled = FALSE, updated_at = $2
		 WHERE provider_id = $1 AND source = $3 AND NOT (slug = ANY($4))`
	return r.withMarkedTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query, providerID, time.Now().UTC(), source, keepSlugs)
		return err
	})
}

func (r *Repository) ListProviders(ctx context.Context) ([]domain.Provider, error) {
	const query = `
		SELECT id, code, display_name, wire_format, source, metadata, created_at, updated_at
		  FROM providers_catalog
		 ORDER BY code`
	rows, err := r.conn.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProviders(rows)
}

// modelColumns is the projection both model reads share, kept in one place so
// the two column lists cannot drift out of step with scanModels.
//
// The nullable columns are coalesced because scanModels reads them into value
// types, and pgx fails a scan rather than zeroing a NULL. Every one of them
// predates a writer that only ever sends a Go string or int, so a NULL can only
// come from an ADD COLUMN backfilling existing rows — which is exactly how the
// cache price columns broke this listing once already. cache_read_price and
// cache_write_price are absent here on purpose: 20260827120000 made them
// NOT NULL, so the schema now carries the guarantee and a COALESCE would only
// suggest it does not.
const modelColumns = `
		       m.id, m.provider_id, m.slug,
		       COALESCE(m.external_id, '')   AS external_id,
		       COALESCE(m.display_name, '')  AS display_name,
		       COALESCE(m.context_window, 0) AS context_window,
		       COALESCE(m.max_output, 0)     AS max_output,
		       COALESCE(m.input_price, '')   AS input_price,
		       COALESCE(m.output_price, '')  AS output_price,
		       m.cache_read_price, m.cache_write_price,
		       m.capabilities, m.enabled, m.source, m.release_date,
		       m.input_modalities, m.output_modalities, m.created_at, m.updated_at`

func (r *Repository) ListModelsByProviderCode(ctx context.Context, providerCode string) ([]domain.Model, error) {
	const query = `
		SELECT` + modelColumns + `
		  FROM models_catalog m
		  JOIN providers_catalog p ON p.id = m.provider_id
		 WHERE ($1 = '' OR p.code = $1)
		 ORDER BY m.release_date DESC NULLS LAST, p.code, m.slug`
	rows, err := r.conn.Pool.Query(ctx, query, providerCode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanModels(rows)
}

func (r *Repository) FindModel(ctx context.Context, providerCode, slug string) (*domain.Model, error) {
	const query = `
		SELECT` + modelColumns + `
		  FROM models_catalog m
		  JOIN providers_catalog p ON p.id = m.provider_id
		 WHERE p.code = $1 AND m.slug = $2`
	rows, err := r.conn.Pool.Query(ctx, query, providerCode, slug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	models, err := scanModels(rows)
	if err != nil {
		return nil, err
	}
	if len(models) == 0 {
		return nil, commonerrors.ErrNotFound
	}
	return &models[0], nil
}

func scanProviders(rows pgx.Rows) ([]domain.Provider, error) {
	var out []domain.Provider
	for rows.Next() {
		var p domain.Provider
		var metadataRaw []byte
		if err := rows.Scan(
			&p.ID, &p.Code, &p.DisplayName, &p.WireFormat, &p.Source, &metadataRaw, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(metadataRaw) > 0 {
			if err := json.Unmarshal(metadataRaw, &p.Metadata); err != nil {
				return nil, fmt.Errorf("scan provider metadata: %w", err)
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func scanModels(rows pgx.Rows) ([]domain.Model, error) {
	var out []domain.Model
	for rows.Next() {
		var m domain.Model
		var capabilitiesRaw []byte
		if err := rows.Scan(
			&m.ID, &m.ProviderID, &m.Slug, &m.ExternalID, &m.DisplayName, &m.ContextWindow, &m.MaxOutput,
			&m.InputPrice, &m.OutputPrice, &m.CacheReadPrice, &m.CacheWritePrice,
			&capabilitiesRaw, &m.Enabled, &m.Source, &m.ReleaseDate,
			&m.InputModalities, &m.OutputModalities, &m.CreatedAt, &m.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(capabilitiesRaw) > 0 {
			if err := json.Unmarshal(capabilitiesRaw, &m.Capabilities); err != nil {
				return nil, fmt.Errorf("scan model capabilities: %w", err)
			}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func marshalJSONB(v map[string]any) ([]byte, error) {
	if len(v) == 0 {
		return nil, nil
	}
	return json.Marshal(v)
}
