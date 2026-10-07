//go:build functional

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

package migrations

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func beginShadowTx(t *testing.T, setup string) (context.Context, pgx.Tx) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	_, err = tx.Exec(ctx, setup+`; SET LOCAL search_path TO pg_temp`)
	require.NoError(t, err)
	return ctx, tx
}

func runTwice(t *testing.T, ctx context.Context, tx pgx.Tx, step func(context.Context, pgx.Tx) error) {
	t.Helper()
	for range 2 {
		require.NoError(t, step(ctx, tx))
	}
}

func sqlStateOf(t *testing.T, ctx context.Context, tx pgx.Tx, query string, args ...any) string {
	t.Helper()
	savepoint, err := tx.Begin(ctx)
	require.NoError(t, err)
	_, execErr := savepoint.Exec(ctx, query, args...)
	require.NoError(t, savepoint.Rollback(ctx))
	if execErr == nil {
		return ""
	}
	pgErr, ok := errors.AsType[*pgconn.PgError](execErr)
	require.True(t, ok, "exec %q: %v", query, execErr)
	return pgErr.Code
}

func countOf(t *testing.T, ctx context.Context, tx pgx.Tx, query string) int {
	t.Helper()
	var n int
	require.NoError(t, tx.QueryRow(ctx, query).Scan(&n))
	return n
}
