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
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
)

// sessionQuerier is the subset of a pool or pooled connection the session
// identity and owner-role steps need.
type sessionQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// logSessionIdentity logs who the main pool's sessions are: current_user is
// POSTGRES_ROLE when it is set, session_user is always the login.
func logSessionIdentity(ctx context.Context, q sessionQuerier, logger *slog.Logger) {
	var currentUser, sessionUser string
	if err := q.QueryRow(ctx, "SELECT current_user, session_user").Scan(&currentUser, &sessionUser); err != nil {
		logger.Warn("failed to read the postgres session identity", slog.String("error", err.Error()))
		return
	}
	logger.Info("postgres session identity",
		slog.String("current_user", currentUser),
		slog.String("session_user", sessionUser))
}

// Server-side bounds for the reassign. A client-side deadline would make pgx
// close the connection, and with it the migrations advisory lock it holds.
const (
	reassignLockTimeout      = `SET LOCAL lock_timeout = '5s'`
	reassignStatementTimeout = `SET LOCAL statement_timeout = '15s'`
)

// sharedObjectsOwnedByLogin lists the databases other than the current one and
// the tablespaces the login owns. REASSIGN OWNED moves those too, cluster-wide.
const sharedObjectsOwnedByLogin = `
	SELECT COALESCE(string_agg(name, ', ' ORDER BY name), '') FROM (
		SELECT 'database ' || datname AS name FROM pg_database
		WHERE datdba = (SELECT oid FROM pg_roles WHERE rolname = session_user)
		  AND datname <> current_database()
		UNION ALL
		SELECT 'tablespace ' || spcname FROM pg_tablespace
		WHERE spcowner = (SELECT oid FROM pg_roles WHERE rolname = session_user)
	) owned`

// errSharedObjectsOwned means the login owns databases or tablespaces outside
// this database, which REASSIGN OWNED would hand to role as well.
var errSharedObjectsOwned = errors.New("the postgres login owns shared objects outside this database")

// adoptOwnerRole reassigns every object the login owns in this database, and
// the database itself when the login owns it, to role when the login is not
// role itself, so objects created before POSTGRES_ROLE (or by a login that
// bypassed it) stop being owner-only. The reassign is skipped when the login
// owns other databases or tablespaces, since REASSIGN OWNED would move them too.
//
// It fails when anything in this database is still owned by the login
// afterwards: every session runs as role, so those objects would surface later
// as "permission denied", far from the cause. That covers a skipped reassign, a
// membership without INHERIT or SET, and a lock held past the timeout. A
// reassign that fails with nothing left to move is only logged.
func adoptOwnerRole(ctx context.Context, q sessionQuerier, role string, logger *slog.Logger) error {
	var isRole bool
	if err := q.QueryRow(ctx, "SELECT session_user = $1", role).Scan(&isRole); err != nil {
		return fmt.Errorf("compare the postgres login with POSTGRES_ROLE: %w", err)
	}
	if isRole {
		return nil
	}
	reassignErr := reassignOwnedTo(ctx, q, role)
	var remaining int64
	if err := q.QueryRow(ctx, loginOwnedObjectsSQL).Scan(&remaining); err != nil {
		return fmt.Errorf("count objects still owned by the postgres login: %w", err)
	}
	if remaining > 0 {
		return fmt.Errorf("%d objects in this database are still owned by the postgres login, so sessions running as POSTGRES_ROLE %q cannot use them; "+
			"reassign them to %q (the login needs INHERIT and SET on it): %v",
			remaining, role, role, reassignErr)
	}
	if reassignErr != nil {
		logger.Warn("reassign to POSTGRES_ROLE did not run, but the postgres login owns nothing in this database",
			slog.String("role", role),
			slog.String("error", reassignErr.Error()))
		return nil
	}
	logger.Info("reassigned objects owned by the postgres login to POSTGRES_ROLE", slog.String("role", role))
	return nil
}

// loginOwnedObjectsSQL counts objects in the current database owned by the
// login. Databases and tablespaces are shared objects (dbid 0), not counted.
const loginOwnedObjectsSQL = `SELECT count(*) FROM pg_shdepend
	WHERE deptype = 'o'
	  AND refobjid = (SELECT oid FROM pg_roles WHERE rolname = session_user)
	  AND dbid = (SELECT oid FROM pg_database WHERE datname = current_database())`

func reassignOwnedTo(ctx context.Context, q sessionQuerier, role string) error {
	tx, err := q.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // No-op after Commit.

	for _, stmt := range []string{reassignLockTimeout, reassignStatementTimeout} {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("set timeout: %w", err)
		}
	}
	// REASSIGN OWNED needs the login's own privileges, not the session role's.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE NONE"); err != nil {
		return fmt.Errorf("reset role: %w", err)
	}
	var shared string
	if err := tx.QueryRow(ctx, sharedObjectsOwnedByLogin).Scan(&shared); err != nil {
		return fmt.Errorf("list shared objects: %w", err)
	}
	if shared != "" {
		return fmt.Errorf("%w: %s", errSharedObjectsOwned, shared)
	}
	if _, err := tx.Exec(ctx, "REASSIGN OWNED BY SESSION_USER TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		return fmt.Errorf("reassign owned: %w", err)
	}
	return tx.Commit(ctx)
}
