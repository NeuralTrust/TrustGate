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
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier runs read queries. A pool satisfies it, and so does a read snapshot.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type snapshotContextKey struct{}

// readSnapshot is a Postgres snapshot exported by an open read-only
// transaction. Every query made through it runs in its own short transaction
// that imports the snapshot, so concurrent readers each hold their own
// connection and all of them see the database as of one instant.
type readSnapshot struct {
	pool *pgxpool.Pool
	id   string
}

var snapshotIDPattern = regexp.MustCompile(`^[0-9A-Fa-f]+(-[0-9A-Fa-f]+)+$`)

// ReadConsistent runs fn with a context whose reads, made through Reader,
// all see the database as of one instant. Paged scans made inside it cannot
// skip or repeat rows that concurrent writes insert or delete. A context that
// already carries a snapshot is reused.
func (c *Connection) ReadConsistent(ctx context.Context, fn func(context.Context) error) error {
	if _, ok := ctx.Value(snapshotContextKey{}).(*readSnapshot); ok {
		return fn(ctx)
	}
	if c == nil || c.Pool == nil {
		return errors.New("database: nil connection")
	}
	tx, err := c.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("database: begin read snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var id string
	if err := tx.QueryRow(ctx, `SELECT pg_export_snapshot()`).Scan(&id); err != nil {
		return fmt.Errorf("database: export read snapshot: %w", err)
	}
	if !snapshotIDPattern.MatchString(id) {
		return fmt.Errorf("database: unexpected snapshot id %q", id)
	}
	return fn(context.WithValue(ctx, snapshotContextKey{}, &readSnapshot{pool: c.Pool, id: id}))
}

// Reader returns the read snapshot ctx carries for pool, or pool itself.
func Reader(ctx context.Context, pool *pgxpool.Pool) Querier {
	if s, ok := ctx.Value(snapshotContextKey{}).(*readSnapshot); ok && s.pool == pool {
		return s
	}
	return pool
}

func (s *readSnapshot) begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("database: begin snapshot read: %w", err)
	}
	// SET TRANSACTION SNAPSHOT takes no bind parameters; the id is
	// server-generated and checked against snapshotIDPattern.
	if _, err := tx.Exec(ctx, "SET TRANSACTION SNAPSHOT '"+s.id+"'"); err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("database: import read snapshot: %w", err)
	}
	return tx, nil
}

func (s *readSnapshot) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, err
	}
	return &snapshotRows{Rows: rows, tx: tx, ctx: ctx}, nil
}

func (s *readSnapshot) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx, err := s.begin(ctx)
	if err != nil {
		return errRow{err: err}
	}
	return &snapshotRow{row: tx.QueryRow(ctx, sql, args...), tx: tx, ctx: ctx}
}

// snapshotRows ends its transaction when the rows are closed or exhausted.
type snapshotRows struct {
	pgx.Rows
	tx   pgx.Tx
	ctx  context.Context
	done bool
}

func (r *snapshotRows) Next() bool {
	if r.Rows.Next() {
		return true
	}
	r.finish()
	return false
}

func (r *snapshotRows) Close() {
	r.Rows.Close()
	r.finish()
}

func (r *snapshotRows) finish() {
	if r.done {
		return
	}
	r.done = true
	r.Rows.Close()
	_ = r.tx.Rollback(context.WithoutCancel(r.ctx))
}

type snapshotRow struct {
	row pgx.Row
	tx  pgx.Tx
	ctx context.Context
}

func (r *snapshotRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	_ = r.tx.Rollback(context.WithoutCancel(r.ctx))
	return err
}

type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }
