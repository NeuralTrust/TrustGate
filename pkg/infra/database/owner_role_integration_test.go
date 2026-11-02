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

package database

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// TestIntegration_OwnerRole needs a superuser on a disposable Postgres (the
// TEST_DB_* env vars, defaulting to the local functional database). It creates
// a login and an owner role, checks the main pool runs as the owner role, and
// that the adopt step hands the owner role a table the login created.
func TestIntegration_OwnerRole(t *testing.T) {
	ctx := context.Background()
	admin := integrationConfig("", envOr("TEST_DB_USER", "postgres"), envOr("TEST_DB_PASSWORD", "postgres"))
	adminConn, err := NewConnection(ctx, admin)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI must provide Postgres for the owner-role integration test: %v", err)
		}
		t.Skipf("no reachable Postgres for the owner-role integration test: %v", err)
	}
	t.Cleanup(adminConn.Close)

	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	owner, login, table, sibling := "owner_"+suffix, "login_"+suffix, "owned_"+suffix, "sibling_"+suffix
	ownerID, loginID, siblingID := pgx.Identifier{owner}.Sanitize(), pgx.Identifier{login}.Sanitize(), pgx.Identifier{sibling}.Sanitize()
	for _, stmt := range []string{
		"CREATE ROLE " + ownerID + " NOLOGIN",
		"CREATE ROLE " + loginID + " LOGIN PASSWORD 'login'",
		"GRANT " + ownerID + " TO " + loginID,
		"GRANT CREATE ON SCHEMA public TO " + ownerID + ", " + loginID,
	} {
		_, err := adminConn.Pool.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	t.Cleanup(func() {
		for _, stmt := range []string{
			"DROP DATABASE IF EXISTS " + siblingID,
			"DROP TABLE IF EXISTS public." + pgx.Identifier{table}.Sanitize(),
			"DROP OWNED BY " + loginID + ", " + ownerID,
			"DROP ROLE IF EXISTS " + loginID,
			"DROP ROLE IF EXISTS " + ownerID,
		} {
			_, _ = adminConn.Pool.Exec(ctx, stmt) // Best-effort cleanup of a disposable database.
		}
	})

	// Before POSTGRES_ROLE: the login creates a table it alone owns.
	plain, err := NewConnection(ctx, integrationConfig("", login, "login"))
	require.NoError(t, err)
	_, err = plain.Pool.Exec(ctx, "CREATE TABLE public."+pgx.Identifier{table}.Sanitize()+" (id int)")
	plain.Close()
	require.NoError(t, err)
	require.Equal(t, login, tableOwner(ctx, t, adminConn, table))

	conn, err := NewConnection(ctx, integrationConfig(owner, login, "login"))
	require.NoError(t, err)
	t.Cleanup(conn.Close)

	var currentUser, sessionUser string
	require.NoError(t, conn.Pool.QueryRow(ctx, "SELECT current_user, session_user").Scan(&currentUser, &sessionUser))
	require.Equal(t, owner, currentUser)
	require.Equal(t, login, sessionUser)

	adopt := func() error {
		pooled, err := conn.Pool.Acquire(ctx)
		require.NoError(t, err)
		defer pooled.Release()
		return adoptOwnerRole(ctx, pooled, owner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}

	// A login that owns another database is left alone: REASSIGN OWNED would
	// hand that database to the owner role too.
	_, err = adminConn.Pool.Exec(ctx, "CREATE DATABASE "+siblingID+" OWNER "+loginID)
	require.NoError(t, err)
	require.ErrorContains(t, adopt(), "still owned by the postgres login",
		"a skipped reassign that leaves the table to the login must fail startup")
	require.Equal(t, login, tableOwner(ctx, t, adminConn, table))
	var siblingOwner string
	require.NoError(t, adminConn.Pool.QueryRow(ctx, "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = $1", sibling).Scan(&siblingOwner))
	require.Equal(t, login, siblingOwner)
	_, err = adminConn.Pool.Exec(ctx, "DROP DATABASE "+siblingID)
	require.NoError(t, err)

	// A lock held by another session makes the reassign give up after
	// lock_timeout, and the session (with its advisory lock) stays usable.
	holder, err := adminConn.Pool.Begin(ctx)
	require.NoError(t, err)
	_, err = holder.Exec(ctx, "LOCK TABLE public."+pgx.Identifier{table}.Sanitize()+" IN ACCESS SHARE MODE")
	require.NoError(t, err)
	pooled, err := conn.Pool.Acquire(ctx)
	require.NoError(t, err)
	started := time.Now()
	require.Error(t, adoptOwnerRole(ctx, pooled, owner, slog.New(slog.NewTextHandler(io.Discard, nil))),
		"a reassign that times out leaves the table to the login and must fail startup")
	require.Less(t, time.Since(started), 10*time.Second)
	var one int
	require.NoError(t, pooled.QueryRow(ctx, "SELECT 1").Scan(&one), "the session must survive the lock timeout")
	pooled.Release()
	require.NoError(t, holder.Rollback(ctx))
	require.Equal(t, login, tableOwner(ctx, t, adminConn, table))

	require.NoError(t, adopt())
	require.Equal(t, owner, tableOwner(ctx, t, adminConn, table))

	_, err = NewConnection(ctx, integrationConfig("not_a_member_"+suffix, login, "login"))
	require.Error(t, err, "a role the login is not a member of must fail the connection")

	// PGOPTIONS naming the same role, as deployments still set it, must coexist.
	t.Setenv("PGOPTIONS", "-c role="+owner)
	both, err := NewConnection(ctx, integrationConfig(owner, login, "login"))
	require.NoError(t, err)
	defer both.Close()
	require.NoError(t, both.Pool.QueryRow(ctx, "SELECT current_user").Scan(&currentUser))
	require.Equal(t, owner, currentUser)
}

func tableOwner(ctx context.Context, t *testing.T, conn *Connection, table string) string {
	t.Helper()
	var owner string
	require.NoError(t, conn.Pool.QueryRow(ctx, "SELECT tableowner FROM pg_tables WHERE schemaname = 'public' AND tablename = $1", table).Scan(&owner))
	return owner
}

func integrationConfig(role, user, password string) *config.DatabaseConfig {
	port := 5432
	if raw := os.Getenv("TEST_DB_PORT"); raw != "" {
		if p, err := strconv.Atoi(raw); err == nil {
			port = p
		}
	}
	return &config.DatabaseConfig{
		Role:              role,
		Host:              envOr("TEST_DB_HOST", "localhost"),
		Port:              port,
		User:              user,
		Password:          password,
		Name:              envOr("TEST_DB_NAME", "trustgate_functional"),
		SSLMode:           envOr("TEST_DB_SSLMODE", "disable"),
		MinConns:          0,
		MaxConns:          2,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   time.Minute,
		HealthCheckPeriod: time.Minute,
		ConnectTimeout:    5 * time.Second,
	}
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
