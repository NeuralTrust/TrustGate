//go:build integration

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

package configsyncconn

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	// Register the config_sync_connections migration (and the rest of the schema).
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
)

// setupRepository builds a connection to a local Postgres and applies pending
// migrations. It skips the test when no database is reachable so the integration
// suite can run in environments without Postgres. Connection settings come from
// the TEST_DB_* env vars, defaulting to the local functional database.
func setupRepository(t *testing.T) (*database.Connection, *Repository) {
	t.Helper()
	ctx := context.Background()

	port := 5432
	if raw := os.Getenv("TEST_DB_PORT"); raw != "" {
		if p, err := strconv.Atoi(raw); err == nil {
			port = p
		}
	}
	cfg := &config.DatabaseConfig{
		Host:              envOr("TEST_DB_HOST", "localhost"),
		Port:              port,
		User:              envOr("TEST_DB_USER", "postgres"),
		Password:          envOr("TEST_DB_PASSWORD", "postgres"),
		Name:              envOr("TEST_DB_NAME", "trustgate_functional"),
		SSLMode:           envOr("TEST_DB_SSLMODE", "disable"),
		MinConns:          1,
		MaxConns:          5,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   30 * time.Minute,
		HealthCheckPeriod: time.Minute,
		ConnectTimeout:    5 * time.Second,
	}

	conn, err := database.NewConnection(ctx, cfg)
	if err != nil {
		t.Skipf("no reachable Postgres for the configsyncconn integration test: %v", err)
	}
	t.Cleanup(conn.Close)

	// The migration is idempotent: applying twice must not fail.
	if err := database.NewMigrationsManager(conn.Pool).ApplyPending(ctx); err != nil {
		t.Fatalf("ApplyPending: %v", err)
	}
	if err := database.NewMigrationsManager(conn.Pool).ApplyPending(ctx); err != nil {
		t.Fatalf("ApplyPending (re-run): %v", err)
	}

	if _, err := conn.Pool.Exec(ctx, `DELETE FROM config_sync_connections`); err != nil {
		t.Fatalf("truncate config_sync_connections: %v", err)
	}
	return conn, NewRepository(conn)
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func find(conns []Connection, scope, instanceID string) (Connection, bool) {
	for _, c := range conns {
		if c.Scope == scope && c.InstanceID == instanceID {
			return c, true
		}
	}
	return Connection{}, false
}

func TestIntegration_ConnectAckDisconnectLifecycle(t *testing.T) {
	_, repo := setupRepository(t)
	ctx := context.Background()

	if err := repo.MarkConnected(ctx, "tenant-a", "dp-1"); err != nil {
		t.Fatalf("MarkConnected: %v", err)
	}
	connected, _ := mustGet(t, repo, "tenant-a", "dp-1")
	if connected.State != "connected" {
		t.Fatalf("state after connect = %q, want connected", connected.State)
	}
	firstSeen := connected.FirstSeen

	if err := repo.MarkAck(ctx, "tenant-a", "dp-1", "v7"); err != nil {
		t.Fatalf("MarkAck: %v", err)
	}
	acked, _ := mustGet(t, repo, "tenant-a", "dp-1")
	if acked.AppliedVersion != "v7" || acked.State != "connected" {
		t.Fatalf("after ack = %+v, want applied_version v7 / connected", acked)
	}

	if err := repo.MarkDisconnected(ctx, "tenant-a", "dp-1"); err != nil {
		t.Fatalf("MarkDisconnected: %v", err)
	}
	gone, _ := mustGet(t, repo, "tenant-a", "dp-1")
	if gone.State != "disconnected" {
		t.Fatalf("state after disconnect = %q, want disconnected", gone.State)
	}
	if gone.AppliedVersion != "v7" {
		t.Fatalf("applied_version must survive disconnect, got %q", gone.AppliedVersion)
	}

	// A reconnect must preserve first_seen (upsert, not insert).
	if err := repo.MarkConnected(ctx, "tenant-a", "dp-1"); err != nil {
		t.Fatalf("MarkConnected (reconnect): %v", err)
	}
	reconnected, _ := mustGet(t, repo, "tenant-a", "dp-1")
	if !reconnected.FirstSeen.Equal(firstSeen) {
		t.Fatalf("first_seen changed on reconnect: %v -> %v", firstSeen, reconnected.FirstSeen)
	}
	if reconnected.State != "connected" {
		t.Fatalf("state after reconnect = %q, want connected", reconnected.State)
	}
}

func TestIntegration_ListScopeIsolation(t *testing.T) {
	_, repo := setupRepository(t)
	ctx := context.Background()

	if err := repo.MarkConnected(ctx, "tenant-a", "dp-1"); err != nil {
		t.Fatalf("MarkConnected a/dp-1: %v", err)
	}
	if err := repo.MarkConnected(ctx, "tenant-a", "dp-2"); err != nil {
		t.Fatalf("MarkConnected a/dp-2: %v", err)
	}
	if err := repo.MarkConnected(ctx, "tenant-b", "dp-9"); err != nil {
		t.Fatalf("MarkConnected b/dp-9: %v", err)
	}

	scoped, err := repo.List(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("List(tenant-a): %v", err)
	}
	if len(scoped) != 2 {
		t.Fatalf("List(tenant-a) = %d rows, want 2", len(scoped))
	}
	if _, ok := find(scoped, "tenant-b", "dp-9"); ok {
		t.Fatal("List(tenant-a) leaked a tenant-b connection")
	}

	unknown, err := repo.List(ctx, "tenant-missing")
	if err != nil {
		t.Fatalf("List(tenant-missing): %v", err)
	}
	if len(unknown) != 0 {
		t.Fatalf("List(unknown scope) = %d rows, want 0", len(unknown))
	}

	all, err := repo.List(ctx, "")
	if err != nil {
		t.Fatalf("List(all): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("List(empty scope) = %d rows, want all 3", len(all))
	}
}

func mustGet(t *testing.T, repo *Repository, scope, instanceID string) (Connection, bool) {
	t.Helper()
	conns, err := repo.List(context.Background(), scope)
	if err != nil {
		t.Fatalf("List(%q): %v", scope, err)
	}
	c, ok := find(conns, scope, instanceID)
	if !ok {
		t.Fatalf("connection %s/%s not found", scope, instanceID)
	}
	return c, ok
}
