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

// adoptOwnerRole reassigns every object the login owns in this database to
// role when the login is not role itself, so objects created before
// POSTGRES_ROLE (or by a login that bypassed it) stop being owner-only. It
// never fails: a login that cannot reassign (it owns the database without
// CREATEDB, or its membership lacks INHERIT) is logged and startup continues.
func adoptOwnerRole(ctx context.Context, q sessionQuerier, role string, logger *slog.Logger) {
	var isRole bool
	if err := q.QueryRow(ctx, "SELECT session_user = $1", role).Scan(&isRole); err != nil {
		logger.Warn("failed to compare the postgres login with POSTGRES_ROLE; skipping reassign",
			slog.String("role", role),
			slog.String("error", err.Error()))
		return
	}
	if isRole {
		return
	}
	if err := reassignOwnedTo(ctx, q, role); err != nil {
		logger.Warn("failed to reassign objects owned by the postgres login to POSTGRES_ROLE; continuing",
			slog.String("role", role),
			slog.String("error", err.Error()))
		return
	}
	logger.Info("reassigned objects owned by the postgres login to POSTGRES_ROLE", slog.String("role", role))
}

func reassignOwnedTo(ctx context.Context, q sessionQuerier, role string) error {
	tx, err := q.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // No-op after Commit.

	// REASSIGN OWNED needs the login's own privileges, not the session role's.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE NONE"); err != nil {
		return fmt.Errorf("reset role: %w", err)
	}
	if _, err := tx.Exec(ctx, "REASSIGN OWNED BY SESSION_USER TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		return fmt.Errorf("reassign owned: %w", err)
	}
	return tx.Commit(ctx)
}
