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

package postgres

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// integrationDSN returns the DSN for the sensible-store test database, or skips
// the test when it is not configured so unit CI stays offline.
func integrationDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("SENSIBLE_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("SENSIBLE_PG_TEST_DSN not set; skipping postgres integration test")
	}
	return dsn
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRunMigrationsIsIdempotent(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, integrationDSN(t))
	require.NoError(t, err)
	defer pool.Close()

	require.NoError(t, runMigrations(ctx, pool, discardLogger()))
	require.NoError(t, runMigrations(ctx, pool, discardLogger()))

	var count int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM "+metrics.MigrationVersionTable).Scan(&count))
	require.Equal(t, len(metrics.Migrations()), count)
}

func TestRunMigrationsRenamesLegacyVersionTable(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, integrationDSN(t))
	require.NoError(t, err)
	defer pool.Close()

	_, err = pool.Exec(ctx, "DROP TABLE IF EXISTS "+metrics.MigrationVersionTable+", "+legacyVersionTableName)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+legacyVersionTableName)
	})

	_, err = pool.Exec(ctx, "CREATE TABLE "+legacyVersionTableName+` (
    id         TEXT        PRIMARY KEY,
    name       TEXT        NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO "+legacyVersionTableName+" (id, name) VALUES ('0001', 'create_trustgate_data')")
	require.NoError(t, err)

	require.NoError(t, runMigrations(ctx, pool, discardLogger()))

	var legacy *string
	require.NoError(t, pool.QueryRow(ctx, "SELECT to_regclass('"+legacyVersionTableName+"')::text").Scan(&legacy))
	require.Nil(t, legacy)

	var count int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM "+metrics.MigrationVersionTable).Scan(&count))
	require.Equal(t, len(metrics.Migrations()), count)
}

func TestExporterInsertsSensibleRowIdempotently(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, integrationDSN(t))
	require.NoError(t, err)
	require.NoError(t, runMigrations(ctx, pool, discardLogger()))

	e := newExporter(pool, metrics.TableName, discardLogger())
	defer e.Close()

	resp := "hello-resp"
	trace := "trace-" + time.Now().Format("150405.000000000")
	evt := &events.Event{
		TraceID:    trace,
		GatewayID:  "g",
		TenantID:   "tm",
		OccurredOn: time.Now().UnixMilli(),
		Request:    events.Request{Body: "hello-req"},
		Response:   events.Response{Body: &resp},

		ClientTraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		MCPSessionID:  "mcp-sess-1",
	}

	require.NoError(t, e.Publish(ctx, evt))
	require.NoError(t, e.Publish(ctx, evt))

	var reqBody string
	var respBody *string
	var schemaVer int
	var clientTraceID, mcpSessionID *string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT request_body, response_body, schema_version, client_trace_id, mcp_session_id FROM "+metrics.TableName+" WHERE trace_id=$1", trace,
	).Scan(&reqBody, &respBody, &schemaVer, &clientTraceID, &mcpSessionID))
	require.Equal(t, "hello-req", reqBody)
	require.NotNil(t, respBody)
	require.Equal(t, "hello-resp", *respBody)
	require.Equal(t, metrics.SchemaVersion, schemaVer)
	require.NotNil(t, clientTraceID)
	require.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", *clientTraceID)
	require.NotNil(t, mcpSessionID)
	require.Equal(t, "mcp-sess-1", *mcpSessionID)

	_, err = pool.Exec(ctx, "DELETE FROM "+metrics.TableName+" WHERE trace_id=$1", trace)
	require.NoError(t, err)
}

func TestRunMigrationsUpgradesAnExistingTableAndOldRowsReadNull(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, integrationDSN(t))
	require.NoError(t, err)
	defer pool.Close()

	_, err = pool.Exec(ctx, "DROP TABLE IF EXISTS "+metrics.TableName+", "+metrics.MigrationVersionTable)
	require.NoError(t, err)
	first := metrics.Migrations()[0]
	_, err = pool.Exec(ctx, first.UpSQL)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, metrics.MigrationVersionTableDDL)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO "+metrics.MigrationVersionTable+" (id, name) VALUES ($1, $2)", first.ID, first.Name)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO "+metrics.TableName+
		" (trace_id, gateway_id, occurred_on, schema_version, request_body) VALUES ('old-row', 'g', 1, 2, 'b')")
	require.NoError(t, err)

	require.NoError(t, runMigrations(ctx, pool, discardLogger()))

	var clientTraceID, mcpSessionID *string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT client_trace_id, mcp_session_id FROM "+metrics.TableName+" WHERE trace_id='old-row'",
	).Scan(&clientTraceID, &mcpSessionID))
	require.Nil(t, clientTraceID)
	require.Nil(t, mcpSessionID)

	_, err = pool.Exec(ctx, "DELETE FROM "+metrics.TableName+" WHERE trace_id='old-row'")
	require.NoError(t, err)
}
