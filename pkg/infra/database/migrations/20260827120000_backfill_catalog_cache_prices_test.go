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
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestBackfillCatalogCachePricesMigration(t *testing.T) {
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	// Mirrors the state 20260826120000 leaves behind: the columns exist, are
	// nullable, and every row that predates them holds NULL.
	const setup = `
		CREATE TEMP TABLE models_catalog (
			slug              TEXT PRIMARY KEY,
			cache_read_price  TEXT,
			cache_write_price TEXT
		) ON COMMIT DROP;
		SET LOCAL search_path TO pg_temp;
		INSERT INTO models_catalog (slug, cache_read_price, cache_write_price) VALUES
			('legacy-both-null', NULL, NULL),
			('legacy-read-null', NULL, '0.30'),
			('already-priced',   '0.10', '0.20');`
	if _, err := tx.Exec(ctx, setup); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := upBackfillCatalogCachePrices(ctx, tx); err != nil {
		t.Fatalf("up: %v", err)
	}

	assertNoNullCachePrices(t, ctx, tx)
	assertCachePrices(t, ctx, tx, "legacy-both-null", "", "")
	assertCachePrices(t, ctx, tx, "legacy-read-null", "", "0.30")
	// Rows that already carried a price must survive the backfill untouched.
	assertCachePrices(t, ctx, tx, "already-priced", "0.10", "0.20")

	// NOT NULL has to be enforced, not merely backfilled: the point of the
	// migration is that the reader's `string` can never meet a NULL again.
	// The insert runs inside a savepoint so its failure does not poison tx.
	assertRejectsNullCacheRead(t, ctx, tx)

	// The default is what keeps a writer that omits the columns from
	// reintroducing the NULLs this migration just removed.
	if _, err := tx.Exec(ctx, `INSERT INTO models_catalog (slug) VALUES ('defaulted')`); err != nil {
		t.Fatalf("insert relying on default: %v", err)
	}
	assertCachePrices(t, ctx, tx, "defaulted", "", "")

	if err := downBackfillCatalogCachePrices(ctx, tx); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO models_catalog (slug, cache_read_price) VALUES ('reopened', NULL)`,
	); err != nil {
		t.Fatalf("insert NULL after down: %v", err)
	}

	// Reapplying has to cope with the NULL that down let back in, which is the
	// only thing that makes this migration safe to replay.
	if err := upBackfillCatalogCachePrices(ctx, tx); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	assertNoNullCachePrices(t, ctx, tx)
	assertCachePrices(t, ctx, tx, "reopened", "", "")
}

func assertRejectsNullCacheRead(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		t.Fatalf("savepoint: %v", err)
	}
	defer func() { _ = savepoint.Rollback(context.Background()) }()
	if _, err := savepoint.Exec(ctx,
		`INSERT INTO models_catalog (slug, cache_read_price) VALUES ('rejected', NULL)`,
	); err == nil {
		t.Fatal("insert with NULL cache_read_price succeeded, want NOT NULL violation")
	}
}

func assertNoNullCachePrices(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	var remaining int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM models_catalog
		 WHERE cache_read_price IS NULL OR cache_write_price IS NULL`,
	).Scan(&remaining); err != nil {
		t.Fatalf("count NULL cache prices: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("rows with NULL cache prices = %d, want 0", remaining)
	}
}

func assertCachePrices(t *testing.T, ctx context.Context, tx pgx.Tx, slug, wantRead, wantWrite string) {
	t.Helper()
	var read, write string
	if err := tx.QueryRow(ctx,
		`SELECT cache_read_price, cache_write_price FROM models_catalog WHERE slug = $1`,
		slug,
	).Scan(&read, &write); err != nil {
		t.Fatalf("read cache prices for %s: %v", slug, err)
	}
	if read != wantRead || write != wantWrite {
		t.Fatalf("%s prices = (%q, %q), want (%q, %q)", slug, read, write, wantRead, wantWrite)
	}
}
