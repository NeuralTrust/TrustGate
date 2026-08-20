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
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	legacyWithPayload    = "00000000-0000-0000-0000-000000000001"
	legacyWithoutPayload = "00000000-0000-0000-0000-000000000002"
	nativeOAuth2         = "00000000-0000-0000-0000-000000000003"
)

func TestUnifyOIDCIntoOAuth2Migration(t *testing.T) {
	ctx, tx := setupUnifyOIDCFixture(t)

	if err := upUnifyOIDCIntoOAuth2(ctx, tx); err != nil {
		t.Fatalf("up: %v", err)
	}

	assertAuthType(t, ctx, tx, legacyWithPayload, "oauth2")
	assertAuthType(t, ctx, tx, legacyWithoutPayload, "oauth2")
	assertAuthType(t, ctx, tx, nativeOAuth2, "oauth2")
	assertPayloadKey(t, ctx, tx, legacyWithPayload, "oauth2")
	assertNoPayloadKey(t, ctx, tx, legacyWithPayload, "oidc")
	assertIssuer(t, ctx, tx, legacyWithPayload, "oauth2", "https://legacy.example.com")
	assertMarkedRows(t, ctx, tx, 2)
	assertConstraintAllows(t, ctx, tx, false)

	if err := downUnifyOIDCIntoOAuth2(ctx, tx); err != nil {
		t.Fatalf("down: %v", err)
	}

	assertAuthType(t, ctx, tx, legacyWithPayload, "oidc")
	assertAuthType(t, ctx, tx, legacyWithoutPayload, "oidc")
	assertAuthType(t, ctx, tx, nativeOAuth2, "oauth2")
	assertPayloadKey(t, ctx, tx, legacyWithPayload, "oidc")
	assertNoPayloadKey(t, ctx, tx, legacyWithPayload, "oauth2")
	assertPayloadKey(t, ctx, tx, nativeOAuth2, "oauth2")
	assertIssuer(t, ctx, tx, nativeOAuth2, "oauth2", "https://native.example.com")
	assertMarkerTableGone(t, ctx, tx)
	assertConstraintAllows(t, ctx, tx, true)

	if err := upUnifyOIDCIntoOAuth2(ctx, tx); err != nil {
		t.Fatalf("reapply: %v", err)
	}

	assertAuthType(t, ctx, tx, legacyWithPayload, "oauth2")
	assertPayloadKey(t, ctx, tx, legacyWithPayload, "oauth2")
	assertMarkedRows(t, ctx, tx, 2)
	assertConstraintAllows(t, ctx, tx, false)
}

func TestUnifyOIDCIntoOAuth2DownWithoutMarkersChangesNoRow(t *testing.T) {
	ctx, tx := setupUnifyOIDCFixture(t)

	if _, err := tx.Exec(ctx, `DELETE FROM auths WHERE type = 'oidc'`); err != nil {
		t.Fatalf("drop legacy rows: %v", err)
	}

	if err := downUnifyOIDCIntoOAuth2(ctx, tx); err != nil {
		t.Fatalf("down: %v", err)
	}

	assertAuthType(t, ctx, tx, nativeOAuth2, "oauth2")
	assertPayloadKey(t, ctx, tx, nativeOAuth2, "oauth2")
	assertConstraintAllows(t, ctx, tx, true)
}

func TestUnifyOIDCIntoOAuth2DownCarriesBrokerFieldsIntoOIDCPayload(t *testing.T) {
	ctx, tx := setupUnifyOIDCFixture(t)

	if err := upUnifyOIDCIntoOAuth2(ctx, tx); err != nil {
		t.Fatalf("up: %v", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE auths
		SET config = jsonb_set(config, '{oauth2,client_id}', '"broker-client"')
		WHERE id = $1`, legacyWithPayload,
	); err != nil {
		t.Fatalf("add client_id: %v", err)
	}

	if err := downUnifyOIDCIntoOAuth2(ctx, tx); err != nil {
		t.Fatalf("down: %v", err)
	}

	var clientID string
	if err := tx.QueryRow(ctx,
		`SELECT config -> 'oidc' ->> 'client_id' FROM auths WHERE id = $1`,
		legacyWithPayload,
	).Scan(&clientID); err != nil {
		t.Fatalf("read demoted client_id: %v", err)
	}
	if clientID != "broker-client" {
		t.Fatalf("demoted client_id = %q, want %q", clientID, "broker-client")
	}
}

func setupUnifyOIDCFixture(t *testing.T) (context.Context, pgx.Tx) {
	t.Helper()

	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	// pgx prepares a statement as soon as parameters are bound, and Postgres
	// refuses multiple commands in one prepared statement, so the schema and
	// the fixture rows cannot share an Exec.
	const schema = `
		CREATE TEMP TABLE auths (
			id     UUID PRIMARY KEY,
			type   TEXT NOT NULL,
			config JSONB NOT NULL DEFAULT '{}'::jsonb,
			CONSTRAINT auths_type_check CHECK (type IN ('api_key','oauth2','oidc','mtls'))
		) ON COMMIT DROP;
		SET LOCAL search_path TO pg_temp;`
	if _, err := tx.Exec(ctx, schema); err != nil {
		t.Fatalf("setup schema: %v", err)
	}

	const seed = `
		INSERT INTO auths (id, type, config) VALUES
			($1, 'oidc',   '{"oidc": {"issuer": "https://legacy.example.com", "audiences": ["legacy"]}}'::jsonb),
			($2, 'oidc',   '{}'::jsonb),
			($3, 'oauth2', '{"oauth2": {"issuer": "https://native.example.com", "audiences": ["native"]}}'::jsonb)`
	if _, err := tx.Exec(ctx, seed, legacyWithPayload, legacyWithoutPayload, nativeOAuth2); err != nil {
		t.Fatalf("seed: %v", err)
	}

	return ctx, tx
}

func assertAuthType(t *testing.T, ctx context.Context, tx pgx.Tx, id, want string) {
	t.Helper()
	var got string
	if err := tx.QueryRow(ctx, `SELECT type FROM auths WHERE id = $1`, id).Scan(&got); err != nil {
		t.Fatalf("read type of %s: %v", id, err)
	}
	if got != want {
		t.Fatalf("type of %s = %q, want %q", id, got, want)
	}
}

func assertPayloadKey(t *testing.T, ctx context.Context, tx pgx.Tx, id, key string) {
	t.Helper()
	if !hasPayloadKey(t, ctx, tx, id, key) {
		t.Fatalf("config of %s is missing key %q", id, key)
	}
}

func assertNoPayloadKey(t *testing.T, ctx context.Context, tx pgx.Tx, id, key string) {
	t.Helper()
	if hasPayloadKey(t, ctx, tx, id, key) {
		t.Fatalf("config of %s still carries key %q", id, key)
	}
}

func hasPayloadKey(t *testing.T, ctx context.Context, tx pgx.Tx, id, key string) bool {
	t.Helper()
	var present bool
	if err := tx.QueryRow(ctx,
		`SELECT config ? $2 FROM auths WHERE id = $1`, id, key,
	).Scan(&present); err != nil {
		t.Fatalf("read config of %s: %v", id, err)
	}
	return present
}

func assertIssuer(t *testing.T, ctx context.Context, tx pgx.Tx, id, key, want string) {
	t.Helper()
	var got string
	if err := tx.QueryRow(ctx,
		`SELECT config -> $2 ->> 'issuer' FROM auths WHERE id = $1`, id, key,
	).Scan(&got); err != nil {
		t.Fatalf("read issuer of %s: %v", id, err)
	}
	if got != want {
		t.Fatalf("issuer of %s = %q, want %q", id, got, want)
	}
}

func assertMarkedRows(t *testing.T, ctx context.Context, tx pgx.Tx, want int) {
	t.Helper()
	var got int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM auths_oidc_migration`).Scan(&got); err != nil {
		t.Fatalf("count markers: %v", err)
	}
	if got != want {
		t.Fatalf("markers = %d, want %d", got, want)
	}
}

func assertMarkerTableGone(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	var present bool
	if err := tx.QueryRow(ctx,
		`SELECT to_regclass('auths_oidc_migration') IS NOT NULL`,
	).Scan(&present); err != nil {
		t.Fatalf("look up marker table: %v", err)
	}
	if present {
		t.Fatal("marker table still exists after down")
	}
}

func assertConstraintAllows(t *testing.T, ctx context.Context, tx pgx.Tx, wantOIDC bool) {
	t.Helper()
	var def string
	if err := tx.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		  FROM pg_constraint
		 WHERE conrelid = 'auths'::regclass AND conname = 'auths_type_check'`,
	).Scan(&def); err != nil {
		t.Fatalf("read constraint: %v", err)
	}
	if strings.Contains(def, "'oidc'") != wantOIDC {
		t.Fatalf("constraint %q allows oidc = %t, want %t", def, !wantOIDC, wantOIDC)
	}
}
