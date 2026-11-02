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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func roleTestConfig(role string) *config.DatabaseConfig {
	return &config.DatabaseConfig{
		Login:    config.PostgresLoginDefault,
		Role:     role,
		Host:     "db.example.com",
		Port:     5432,
		User:     "agentgateway_login",
		Password: "s3cret",
		Name:     "agentgateway",
		SSLMode:  "require",
		MaxConns: 1,
	}
}

func TestNewPoolConfig_SetsSessionRole(t *testing.T) {
	conf, err := NewPoolConfig(context.Background(), roleTestConfig("agentgateway"))
	require.NoError(t, err)
	require.Equal(t, "agentgateway", conf.ConnConfig.RuntimeParams["role"])
	require.Equal(t, "agentgateway_login", conf.ConnConfig.User)
}

func TestNewPoolConfig_EmptyRoleSendsNone(t *testing.T) {
	conf, err := NewPoolConfig(context.Background(), roleTestConfig(""))
	require.NoError(t, err)
	_, ok := conf.ConnConfig.RuntimeParams["role"]
	require.False(t, ok, "an empty POSTGRES_ROLE must not send the role startup parameter")
}

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, v := range r.values {
		switch d := dest[i].(type) {
		case *string:
			*d = v.(string)
		case *bool:
			*d = v.(bool)
		}
	}
	return nil
}

type fakeTx struct {
	pgx.Tx
	conn *fakeSessionConn
}

func (t *fakeTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	t.conn.execs = append(t.conn.execs, sql)
	if sql == t.conn.failOn {
		return pgconn.CommandTag{}, errors.New("permission denied to reassign objects")
	}
	return pgconn.CommandTag{}, nil
}

func (t *fakeTx) Commit(context.Context) error {
	t.conn.committed = true
	return nil
}

func (t *fakeTx) Rollback(context.Context) error { return nil }

type fakeSessionConn struct {
	current, session string
	queryErr         error
	failOn           string
	began            bool
	committed        bool
	execs            []string
}

func (c *fakeSessionConn) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	if c.queryErr != nil {
		return fakeRow{err: c.queryErr}
	}
	if len(args) == 1 {
		return fakeRow{values: []any{c.session == args[0]}}
	}
	return fakeRow{values: []any{c.current, c.session}}
}

func (c *fakeSessionConn) Begin(context.Context) (pgx.Tx, error) {
	c.began = true
	return &fakeTx{conn: c}, nil
}

func bufferLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

func TestLogSessionIdentity(t *testing.T) {
	logger, buf := bufferLogger()
	logSessionIdentity(context.Background(), &fakeSessionConn{current: "owner", session: "login"}, logger)
	require.Contains(t, buf.String(), "current_user=owner session_user=login")

	logger, buf = bufferLogger()
	logSessionIdentity(context.Background(), &fakeSessionConn{queryErr: errors.New("conn closed")}, logger)
	require.Contains(t, buf.String(), "level=WARN")
}

func TestAdoptOwnerRole(t *testing.T) {
	const role = `agent"gateway`
	const reassign = `REASSIGN OWNED BY SESSION_USER TO "agent""gateway"`

	t.Run("login that is the role is left alone", func(t *testing.T) {
		logger, _ := bufferLogger()
		conn := &fakeSessionConn{session: role}
		adoptOwnerRole(context.Background(), conn, role, logger)
		require.False(t, conn.began)
	})

	t.Run("login different from the role reassigns with a quoted identifier", func(t *testing.T) {
		logger, buf := bufferLogger()
		conn := &fakeSessionConn{session: "login"}
		adoptOwnerRole(context.Background(), conn, role, logger)
		require.Equal(t, []string{"SET LOCAL ROLE NONE", reassign}, conn.execs)
		require.True(t, conn.committed)
		require.Contains(t, buf.String(), "reassigned objects owned by the postgres login")
	})

	t.Run("reassign failure is a warning, not an error", func(t *testing.T) {
		logger, buf := bufferLogger()
		conn := &fakeSessionConn{session: "login", failOn: reassign}
		adoptOwnerRole(context.Background(), conn, role, logger)
		require.False(t, conn.committed)
		require.Contains(t, buf.String(), "level=WARN")
		require.Contains(t, buf.String(), "permission denied to reassign objects")
	})

	t.Run("comparison failure is a warning", func(t *testing.T) {
		logger, buf := bufferLogger()
		conn := &fakeSessionConn{queryErr: errors.New("conn closed")}
		adoptOwnerRole(context.Background(), conn, role, logger)
		require.False(t, conn.began)
		require.Contains(t, buf.String(), "level=WARN")
	})
}
