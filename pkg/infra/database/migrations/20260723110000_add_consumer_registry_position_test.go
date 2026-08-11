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
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestConsumerRegistryPositionMigration(t *testing.T) {
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

	const consumerID = "00000000-0000-0000-0000-000000000100"
	const registryOne = "00000000-0000-0000-0000-000000000001"
	const registryTwo = "00000000-0000-0000-0000-000000000002"
	const registryThree = "00000000-0000-0000-0000-000000000003"
	const registryFour = "00000000-0000-0000-0000-000000000004"

	const setup = `
		CREATE TEMP TABLE consumer_registry (
			consumer_id UUID NOT NULL,
			registry_id UUID NOT NULL,
			weight INT NOT NULL DEFAULT 1,
			PRIMARY KEY (consumer_id, registry_id)
		) ON COMMIT DROP;
		SET LOCAL search_path TO pg_temp;
		INSERT INTO consumer_registry (consumer_id, registry_id) VALUES
			($1, $2),
			($1, $3),
			($1, $4);`
	if _, err := tx.Exec(ctx, setup, consumerID, registryThree, registryOne, registryTwo); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := upConsumerRegistryPosition(ctx, tx); err != nil {
		t.Fatalf("up: %v", err)
	}
	assertConsumerRegistryPositionObjects(t, ctx, tx, true)
	assertRegistryOrder(t, ctx, tx, []string{registryOne, registryTwo, registryThree})
	assertNullPositionCount(t, ctx, tx, 3)

	if _, err := tx.Exec(ctx,
		`INSERT INTO consumer_registry (consumer_id, registry_id) VALUES ($1, $2)`,
		consumerID,
		registryFour,
	); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	assertRegistryOrder(t, ctx, tx, []string{registryOne, registryTwo, registryThree, registryFour})
	var appendedPosition int64
	if err := tx.QueryRow(ctx,
		`SELECT position FROM consumer_registry WHERE registry_id = $1`,
		registryFour,
	).Scan(&appendedPosition); err != nil {
		t.Fatalf("read appended position: %v", err)
	}
	if appendedPosition != 1 {
		t.Fatalf("appended position = %d, want 1", appendedPosition)
	}

	if err := downConsumerRegistryPosition(ctx, tx); err != nil {
		t.Fatalf("down: %v", err)
	}
	assertConsumerRegistryPositionObjects(t, ctx, tx, false)

	if err := upConsumerRegistryPosition(ctx, tx); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	assertConsumerRegistryPositionObjects(t, ctx, tx, true)
	assertRegistryOrder(t, ctx, tx, []string{registryOne, registryTwo, registryThree, registryFour})
	assertNullPositionCount(t, ctx, tx, 4)
}

func assertRegistryOrder(
	t *testing.T,
	ctx context.Context,
	tx pgx.Tx,
	wantRegistries []string,
) {
	t.Helper()
	var registries []string
	if err := tx.QueryRow(ctx, `
		SELECT array_agg(registry_id::text ORDER BY position NULLS FIRST, registry_id)
		  FROM consumer_registry`,
	).Scan(&registries); err != nil {
		t.Fatalf("read registry order: %v", err)
	}
	if !reflect.DeepEqual(registries, wantRegistries) {
		t.Fatalf("registries = %v, want %v", registries, wantRegistries)
	}
}

func assertNullPositionCount(t *testing.T, ctx context.Context, tx pgx.Tx, want int) {
	t.Helper()
	var count int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM consumer_registry WHERE position IS NULL`,
	).Scan(&count); err != nil {
		t.Fatalf("count null positions: %v", err)
	}
	if count != want {
		t.Fatalf("null positions = %d, want %d", count, want)
	}
}

func assertConsumerRegistryPositionObjects(t *testing.T, ctx context.Context, tx pgx.Tx, want bool) {
	t.Helper()
	var hasColumn bool
	var hasSequence bool
	var ownsSequence bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM pg_attribute
			 WHERE attrelid = 'consumer_registry'::regclass
			   AND attname = 'position'
			   AND NOT attisdropped
		),
		to_regclass('consumer_registry_position_seq') IS NOT NULL,
		EXISTS (
			SELECT 1
			  FROM pg_depend d
			  JOIN pg_class seq ON seq.oid = d.objid
			  JOIN pg_attribute a
			    ON a.attrelid = d.refobjid
			   AND a.attnum = d.refobjsubid
			 WHERE seq.relname = 'consumer_registry_position_seq'
			   AND d.refobjid = 'consumer_registry'::regclass
			   AND a.attname = 'position'
			   AND d.deptype = 'a'
		)`,
	).Scan(&hasColumn, &hasSequence, &ownsSequence); err != nil {
		t.Fatalf("read migration objects: %v", err)
	}
	if hasColumn != want || hasSequence != want || ownsSequence != want {
		t.Fatalf(
			"position objects = column:%t sequence:%t ownership:%t, want %t",
			hasColumn,
			hasSequence,
			ownsSequence,
			want,
		)
	}
}
