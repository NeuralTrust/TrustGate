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

// integrationDSN returns the DSN for the data-store test database, or skips
// the test when it is not configured so unit CI stays offline.
func integrationDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DATA_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("DATA_PG_TEST_DSN not set; skipping postgres integration test")
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

func TestExporterInsertsRawRowIdempotently(t *testing.T) {
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
		TeamID:     "tm",
		OccurredOn: time.Now().UnixMilli(),
		Request:    events.Request{Body: "hello-req"},
		Response:   events.Response{Body: &resp},
	}

	require.NoError(t, e.Publish(ctx, evt))
	require.NoError(t, e.Publish(ctx, evt))

	var reqBody string
	var respBody *string
	var schemaVer int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT request_body, response_body, schema_version FROM "+metrics.TableName+" WHERE trace_id=$1", trace,
	).Scan(&reqBody, &respBody, &schemaVer))
	require.Equal(t, "hello-req", reqBody)
	require.NotNil(t, respBody)
	require.Equal(t, "hello-resp", *respBody)
	require.Equal(t, metrics.SchemaVersion, schemaVer)

	_, err = pool.Exec(ctx, "DELETE FROM "+metrics.TableName+" WHERE trace_id=$1", trace)
	require.NoError(t, err)
}
