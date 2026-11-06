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

// Package outbox provides the pgx-backed adapter for the config-snapshot
// change-marker outbox: an in-transaction appender the admin repositories share,
// plus the drain/prune reads the dispatcher runs.
package outbox

import (
	"context"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Appender inserts a change marker inside a caller-owned transaction so the marker
// commits atomically with the config write that triggered it. The admin
// repositories depend on this narrow interface.
type Appender interface {
	// AppendTx appends a marker that dirties everything.
	AppendTx(ctx context.Context, tx pgx.Tx) error
	// AppendGatewayTx appends a marker that dirties one gateway.
	AppendGatewayTx(ctx context.Context, tx pgx.Tx, gatewayID ids.GatewayID) error
	// AppendCatalogTx appends a marker that dirties the shared catalog.
	AppendCatalogTx(ctx context.Context, tx pgx.Tx) error
}

// Marks collects what one write dirtied, so WithMarkedTx appends the markers
// that name it. A write that records nothing, or records a nil gateway, gets a
// single marker that dirties everything: a writer that cannot name its scope
// always triggers a full compile.
type Marks struct {
	all      bool
	catalog  bool
	gateways []ids.GatewayID
}

// Gateway records that the write dirtied gatewayID.
func (m *Marks) Gateway(gatewayID ids.GatewayID) {
	if gatewayID.IsNil() {
		m.all = true
		return
	}
	for _, seen := range m.gateways {
		if seen == gatewayID {
			return
		}
	}
	m.gateways = append(m.gateways, gatewayID)
}

// Catalog records that the write dirtied the shared catalog.
func (m *Marks) Catalog() {
	m.catalog = true
}

// All records that the write dirtied everything.
func (m *Marks) All() {
	m.all = true
}

func (m *Marks) appendTo(ctx context.Context, tx pgx.Tx, appender Appender) error {
	if appender == nil {
		return nil
	}
	if m.all || (!m.catalog && len(m.gateways) == 0) {
		return appender.AppendTx(ctx, tx)
	}
	if m.catalog {
		if err := appender.AppendCatalogTx(ctx, tx); err != nil {
			return err
		}
	}
	for _, gatewayID := range m.gateways {
		if err := appender.AppendGatewayTx(ctx, tx, gatewayID); err != nil {
			return err
		}
	}
	return nil
}

// WithMarkedTx runs fn inside a transaction and, when it succeeds, appends the
// markers for what fn recorded in marks, so the write and its markers commit
// atomically. A nil appender writes no marker.
func WithMarkedTx(ctx context.Context, conn *database.Connection, appender Appender, fn func(tx pgx.Tx, marks *Marks) error) error {
	return database.WithTx(ctx, conn, func(tx pgx.Tx) error {
		var marks Marks
		if err := fn(tx, &marks); err != nil {
			return err
		}
		return marks.appendTo(ctx, tx, appender)
	})
}

// WithGatewayMarkedTx runs fn inside a transaction and appends one marker for
// gatewayID when it succeeds.
func WithGatewayMarkedTx(ctx context.Context, conn *database.Connection, appender Appender, gatewayID ids.GatewayID, fn func(tx pgx.Tx) error) error {
	return WithMarkedTx(ctx, conn, appender, func(tx pgx.Tx, marks *Marks) error {
		if err := fn(tx); err != nil {
			return err
		}
		marks.Gateway(gatewayID)
		return nil
	})
}

// poolQuerier is the subset of pgxpool.Pool the marker reads and the prune need, kept small to fake in tests.
type poolQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Repository is the pgx adapter over config_snapshot_outbox. It implements the
// infra Appender and the app-side OutboxRepository (drain/prune) contracts.
type Repository struct {
	pool poolQuerier
}

var (
	_ Appender                        = (*Repository)(nil)
	_ configsyncport.OutboxRepository = (*Repository)(nil)
)

// NewRepository builds the outbox repository from the shared connection.
func NewRepository(conn *database.Connection) *Repository {
	return &Repository{pool: conn.Pool}
}

// AppendTx inserts, inside tx, one change marker that dirties everything.
func (r *Repository) AppendTx(ctx context.Context, tx pgx.Tx) error {
	return r.append(ctx, tx, configsyncport.MarkerAll, nil)
}

// AppendGatewayTx inserts, inside tx, one change marker that dirties gatewayID.
func (r *Repository) AppendGatewayTx(ctx context.Context, tx pgx.Tx, gatewayID ids.GatewayID) error {
	if gatewayID.IsNil() {
		return r.AppendTx(ctx, tx)
	}
	return r.append(ctx, tx, configsyncport.MarkerGateway, gatewayID.UUID())
}

// AppendCatalogTx inserts, inside tx, one change marker that dirties the catalog.
func (r *Repository) AppendCatalogTx(ctx context.Context, tx pgx.Tx) error {
	return r.append(ctx, tx, configsyncport.MarkerCatalog, nil)
}

func (r *Repository) append(ctx context.Context, tx pgx.Tx, kind configsyncport.MarkerKind, gatewayID any) error {
	if _, err := tx.Exec(ctx, `INSERT INTO config_snapshot_outbox (kind, gateway_id) VALUES ($1, $2)`, string(kind), gatewayID); err != nil {
		return fmt.Errorf("outbox: append %s change marker: %w", kind, err)
	}
	return nil
}

// ReadSince returns, oldest first, every visible marker whose seq is above
// afterSeq, decoded into what it dirtied, plus the lowest and highest seq left
// in the outbox (zero when it is empty).
func (r *Repository) ReadSince(ctx context.Context, afterSeq int64) ([]configsyncport.Marker, configsyncport.OutboxBounds, error) {
	// One statement so the minimum and the markers share a snapshot; a prune cannot slip between.
	const query = `
		WITH bounds AS (SELECT COALESCE(MIN(seq), 0) AS min_seq, COALESCE(MAX(seq), 0) AS max_seq FROM config_snapshot_outbox)
		SELECT bounds.min_seq, bounds.max_seq, o.seq, o.kind, o.gateway_id
		FROM bounds
		LEFT JOIN config_snapshot_outbox o ON o.seq > $1
		ORDER BY o.seq`
	rows, err := r.pool.Query(ctx, query, afterSeq)
	if err != nil {
		return nil, configsyncport.OutboxBounds{}, fmt.Errorf("outbox: read since %d: %w", afterSeq, err)
	}
	defer rows.Close()
	var (
		markers []configsyncport.Marker
		bounds  configsyncport.OutboxBounds
	)
	for rows.Next() {
		var (
			seq       *int64
			kind      *string
			gatewayID *uuid.UUID
		)
		if err := rows.Scan(&bounds.Min, &bounds.Max, &seq, &kind, &gatewayID); err != nil {
			return nil, configsyncport.OutboxBounds{}, fmt.Errorf("outbox: scan marker: %w", err)
		}
		if seq == nil {
			continue
		}
		markers = append(markers, decodeMarker(*seq, kind, gatewayID))
	}
	if err := rows.Err(); err != nil {
		return nil, configsyncport.OutboxBounds{}, fmt.Errorf("outbox: iterate markers: %w", err)
	}
	return markers, bounds, nil
}

func decodeMarker(seq int64, kind *string, gatewayID *uuid.UUID) configsyncport.Marker {
	marker := configsyncport.Marker{Seq: seq, Kind: configsyncport.MarkerAll}
	if kind == nil {
		return marker
	}
	switch configsyncport.MarkerKind(*kind) {
	case configsyncport.MarkerCatalog:
		marker.Kind = configsyncport.MarkerCatalog
	case configsyncport.MarkerGateway:
		if gatewayID != nil && *gatewayID != uuid.Nil {
			marker.Kind = configsyncport.MarkerGateway
			marker.GatewayID = ids.From[ids.GatewayKind](*gatewayID)
		}
	}
	return marker
}

// ReadSeqs returns, oldest first, the markers among seqs that are visible now.
func (r *Repository) ReadSeqs(ctx context.Context, seqs []int64) ([]configsyncport.Marker, error) {
	if len(seqs) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx, `SELECT seq, kind, gateway_id FROM config_snapshot_outbox WHERE seq = ANY($1) ORDER BY seq`, seqs)
	if err != nil {
		return nil, fmt.Errorf("outbox: read seqs: %w", err)
	}
	defer rows.Close()
	var markers []configsyncport.Marker
	for rows.Next() {
		var (
			seq       int64
			kind      *string
			gatewayID *uuid.UUID
		)
		if err := rows.Scan(&seq, &kind, &gatewayID); err != nil {
			return nil, fmt.Errorf("outbox: scan marker: %w", err)
		}
		markers = append(markers, decodeMarker(seq, kind, gatewayID))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("outbox: iterate markers: %w", err)
	}
	return markers, nil
}

// PruneOlderThan enforces the safety bound so a stuck dispatcher can never grow the
// table unbounded: it deletes markers created before cutoff and, when keepMax > 0,
// any marker beyond the newest keepMax rows. It returns the number deleted.
func (r *Repository) PruneOlderThan(ctx context.Context, cutoff time.Time, keepMax int) (int64, error) {
	if keepMax < 0 {
		keepMax = 0
	}
	const prune = `
		DELETE FROM config_snapshot_outbox
		WHERE created_at < $1
		   OR seq <= COALESCE(
			(SELECT seq FROM config_snapshot_outbox ORDER BY seq DESC OFFSET $2 LIMIT 1),
			0
		   )`
	tag, err := r.pool.Exec(ctx, prune, cutoff, keepMax)
	if err != nil {
		return 0, fmt.Errorf("outbox: prune older than %s: %w", cutoff, err)
	}
	return tag.RowsAffected(), nil
}
