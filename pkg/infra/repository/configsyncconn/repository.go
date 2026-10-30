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

	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"

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
	// LastHeartbeat is nil until the data plane sends one: data planes that
	// predate heartbeats never do, and their stream keeps last_seen fresh.
	LastHeartbeat      *time.Time
	Version            string
	Region             string
	DeploymentType     string
	TrustGuardBaseURL  string
	TrustGuardClientID string
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
// existing row. It clears what an earlier stream reported, so a data plane
// rolled back to a build without heartbeats does not keep showing the newer
// build's report; a data plane that sends heartbeats refills it right after
// its Hello.
func (r *Repository) MarkConnected(ctx context.Context, scope, instanceID string) error {
	const stmt = `
		INSERT INTO config_sync_connections (scope, instance_id, state)
		VALUES ($1, $2, 'connected')
		ON CONFLICT (scope, instance_id)
		DO UPDATE SET state = 'connected', last_seen = NOW(), last_heartbeat = NULL,
			version = '', region = '', deployment_type = '',
			trustguard_base_url = '', trustguard_client_id = ''`
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

// MarkHeartbeat records what the data plane reported and refreshes last_seen.
// It inserts the row when MarkConnected never landed, so a failed write at
// connect time does not hide the stream until it reconnects.
func (r *Repository) MarkHeartbeat(ctx context.Context, scope, instanceID string, hb dataplane.Heartbeat) error {
	const stmt = `
		INSERT INTO config_sync_connections (scope, instance_id, state, last_heartbeat,
			version, region, deployment_type, trustguard_base_url, trustguard_client_id)
		VALUES ($1, $2, 'connected', NOW(), $3, $4, $5, $6, $7)
		ON CONFLICT (scope, instance_id)
		DO UPDATE SET last_seen = NOW(), last_heartbeat = NOW(), state = 'connected',
			version = EXCLUDED.version, region = EXCLUDED.region,
			deployment_type = EXCLUDED.deployment_type,
			trustguard_base_url = EXCLUDED.trustguard_base_url,
			trustguard_client_id = EXCLUDED.trustguard_client_id`
	if _, err := r.pool.Exec(ctx, stmt, scope, instanceID, hb.Version, hb.Region, hb.DeploymentType,
		hb.TrustGuardBaseURL, hb.TrustGuardClientID); err != nil {
		return fmt.Errorf("configsyncconn: mark heartbeat: %w", err)
	}
	return nil
}

// TouchConnected marks the given streams connected and refreshes their
// last_seen in one statement. The caller holds these streams open, so it is
// authoritative: a row that a stale teardown marked disconnected, or that
// MarkConnected never wrote, is restored.
func (r *Repository) TouchConnected(ctx context.Context, keys []dataplane.StreamKey) error {
	if len(keys) == 0 {
		return nil
	}
	scopes := make([]string, len(keys))
	instanceIDs := make([]string, len(keys))
	for i, k := range keys {
		scopes[i] = k.Scope
		instanceIDs[i] = k.InstanceID
	}
	const stmt = `
		INSERT INTO config_sync_connections (scope, instance_id, state)
		SELECT DISTINCT k.scope, k.instance_id, 'connected'
		FROM unnest($1::text[], $2::text[]) AS k(scope, instance_id)
		ON CONFLICT (scope, instance_id)
		DO UPDATE SET state = 'connected', last_seen = NOW()`
	if _, err := r.pool.Exec(ctx, stmt, scopes, instanceIDs); err != nil {
		return fmt.Errorf("configsyncconn: touch connected: %w", err)
	}
	return nil
}

// List returns the connections for scope, or all connections when scope is
// empty, ordered by (scope, instance_id). A nil page returns every match.
func (r *Repository) List(ctx context.Context, scope string, page *listing.Page) ([]Connection, error) {
	limit, offset := 0, 0
	if page != nil {
		p := page.Normalize()
		limit, offset = p.Size, p.Offset()
	}
	const stmt = `
		SELECT scope, instance_id, state, applied_version, first_seen, last_seen,
			last_heartbeat, version, region, deployment_type, trustguard_base_url, trustguard_client_id
		FROM config_sync_connections
		WHERE ($1 = '' OR scope = $1)
		ORDER BY scope, instance_id
		LIMIT NULLIF($2, 0) OFFSET $3`
	rows, err := r.pool.Query(ctx, stmt, scope, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("configsyncconn: list: %w", err)
	}
	defer rows.Close()

	var conns []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.Scope, &c.InstanceID, &c.State, &c.AppliedVersion, &c.FirstSeen, &c.LastSeen,
			&c.LastHeartbeat, &c.Version, &c.Region, &c.DeploymentType, &c.TrustGuardBaseURL, &c.TrustGuardClientID); err != nil {
			return nil, fmt.Errorf("configsyncconn: scan connection: %w", err)
		}
		conns = append(conns, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("configsyncconn: iterate connections: %w", err)
	}
	return conns, nil
}
