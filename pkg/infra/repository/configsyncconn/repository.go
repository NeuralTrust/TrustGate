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

// Package configsyncconn provides the pgx-backed adapter over
// config_sync_connections: the write side the config-sync Hub calls best-effort
// to record data-plane stream lifecycle, and the read side the admin API lists.
// scope is stored and matched opaquely.
package configsyncconn

import (
	"context"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Connection is one persisted data-plane stream lifecycle row.
type Connection struct {
	Scope          string
	InstanceID     string
	State          string
	AppliedVersion string
	FirstSeen      time.Time
	LastSeen       time.Time
}

// poolQuerier is the subset of pgxpool.Pool this repository uses, kept small to
// fake in tests.
type poolQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Repository is the pgx adapter over config_sync_connections.
type Repository struct {
	pool poolQuerier
}

// NewRepository builds the connection repository from the shared connection.
func NewRepository(conn *database.Connection) *Repository {
	return &Repository{pool: conn.Pool}
}

// MarkConnected upserts the stream as connected, preserving first_seen on an
// existing row.
func (r *Repository) MarkConnected(ctx context.Context, scope, instanceID string) error {
	const stmt = `
		INSERT INTO config_sync_connections (scope, instance_id, state)
		VALUES ($1, $2, 'connected')
		ON CONFLICT (scope, instance_id)
		DO UPDATE SET state = 'connected', last_seen = NOW()`
	if _, err := r.pool.Exec(ctx, stmt, scope, instanceID); err != nil {
		return fmt.Errorf("configsyncconn: mark connected: %w", err)
	}
	return nil
}

// MarkAck records the data plane's applied version and refreshes last_seen.
func (r *Repository) MarkAck(ctx context.Context, scope, instanceID, appliedVersion string) error {
	const stmt = `
		UPDATE config_sync_connections
		SET applied_version = $3, last_seen = NOW(), state = 'connected'
		WHERE scope = $1 AND instance_id = $2`
	if _, err := r.pool.Exec(ctx, stmt, scope, instanceID, appliedVersion); err != nil {
		return fmt.Errorf("configsyncconn: mark ack: %w", err)
	}
	return nil
}

// MarkDisconnected records the stream as disconnected and refreshes last_seen.
func (r *Repository) MarkDisconnected(ctx context.Context, scope, instanceID string) error {
	const stmt = `
		UPDATE config_sync_connections
		SET state = 'disconnected', last_seen = NOW()
		WHERE scope = $1 AND instance_id = $2`
	if _, err := r.pool.Exec(ctx, stmt, scope, instanceID); err != nil {
		return fmt.Errorf("configsyncconn: mark disconnected: %w", err)
	}
	return nil
}

// List returns the connections for scope, or all connections when scope is
// empty, ordered by (scope, instance_id).
func (r *Repository) List(ctx context.Context, scope string) ([]Connection, error) {
	const stmt = `
		SELECT scope, instance_id, state, applied_version, first_seen, last_seen
		FROM config_sync_connections
		WHERE ($1 = '' OR scope = $1)
		ORDER BY scope, instance_id`
	rows, err := r.pool.Query(ctx, stmt, scope)
	if err != nil {
		return nil, fmt.Errorf("configsyncconn: list: %w", err)
	}
	defer rows.Close()

	var conns []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.Scope, &c.InstanceID, &c.State, &c.AppliedVersion, &c.FirstSeen, &c.LastSeen); err != nil {
			return nil, fmt.Errorf("configsyncconn: scan connection: %w", err)
		}
		conns = append(conns, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("configsyncconn: iterate connections: %w", err)
	}
	return conns, nil
}
