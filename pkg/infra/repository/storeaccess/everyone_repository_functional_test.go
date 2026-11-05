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

package storeaccess

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func openEveryoneSchema(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	schema := "store_everyone_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open admin pool: %v", err)
	}
	t.Cleanup(admin.Close)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE") })

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET search_path TO "+quoted)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open test pool: %v", err)
	}
	t.Cleanup(pool.Close)

	const setup = `
		CREATE TABLE gateways (id UUID PRIMARY KEY);
		CREATE TABLE store_everyone (
			gateway_id      UUID PRIMARY KEY REFERENCES gateways(id) ON DELETE CASCADE,
			mode            TEXT NOT NULL CHECK (mode IN ('open', 'curated')),
			grants          JSONB NOT NULL DEFAULT '[]'::jsonb,
			excluded_groups JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_at      TIMESTAMPTZ NOT NULL,
			updated_at      TIMESTAMPTZ NOT NULL
		);`
	if _, err := pool.Exec(ctx, setup); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	return ctx, pool
}

func insertGateway(t *testing.T, ctx context.Context, pool *pgxpool.Pool) ids.GatewayID {
	t.Helper()
	gw, err := ids.NewV7[ids.GatewayKind]()
	if err != nil {
		t.Fatalf("gateway id: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO gateways (id) VALUES ($1)`, gw); err != nil {
		t.Fatalf("insert gateway: %v", err)
	}
	return gw
}

func TestEveryoneRepositoryRoundTrip(t *testing.T) {
	ctx, pool := openEveryoneSchema(t)
	repo := NewEveryoneRepository(&database.Connection{Pool: pool}, nil)
	gw := insertGateway(t, ctx, pool)
	other := insertGateway(t, ctx, pool)

	if got, err := repo.GetEveryone(ctx, gw); err != nil || got != nil {
		t.Fatalf("a gateway without Everyone must read nil, got %+v / %v", got, err)
	}

	reg := ids.New[ids.RegistryKind]()
	e, err := domain.NewEveryone(gw, "curated",
		[]domain.EveryoneGrant{{CatalogCode: "github"}, {CatalogCode: "snowflake", RegistryID: reg}},
		[]string{"Contractors"})
	if err != nil {
		t.Fatalf("NewEveryone: %v", err)
	}
	if err := repo.UpsertEveryone(ctx, e); err != nil {
		t.Fatalf("UpsertEveryone: %v", err)
	}
	got, err := repo.GetEveryone(ctx, gw)
	if err != nil || got == nil {
		t.Fatalf("GetEveryone: %+v / %v", got, err)
	}
	if got.Mode != "curated" || len(got.Grants) != 2 || got.Grants[0].IsInstance() || got.Grants[1].RegistryID != reg ||
		len(got.ExcludedGroups) != 1 || got.ExcludedGroups[0] != "Contractors" {
		t.Fatalf("round trip lost data: %+v", got)
	}

	open, _ := domain.NewEveryone(gw, "open", nil, nil)
	if err := repo.UpsertEveryone(ctx, open); err != nil {
		t.Fatalf("replace: %v", err)
	}
	got, _ = repo.GetEveryone(ctx, gw)
	if got.Mode != "open" || len(got.Grants) != 0 || len(got.ExcludedGroups) != 0 {
		t.Fatalf("replace must overwrite every field, got %+v", got)
	}

	second, _ := domain.NewEveryone(other, "open", nil, []string{"Sales"})
	if err := repo.UpsertEveryone(ctx, second); err != nil {
		t.Fatalf("second gateway: %v", err)
	}
	all, total, err := repo.ListEveryone(ctx, 1, 1)
	if err != nil || total != 2 || len(all) != 1 {
		t.Fatalf("paging: %d items, total %d, err %v", len(all), total, err)
	}

	if err := repo.DeleteEveryone(ctx, gw); err != nil {
		t.Fatalf("DeleteEveryone: %v", err)
	}
	if err := repo.DeleteEveryone(ctx, gw); err != nil {
		t.Fatalf("deleting a missing object must not fail: %v", err)
	}
	if got, _ := repo.GetEveryone(ctx, gw); got != nil {
		t.Fatalf("a deleted object must read nil, got %+v", got)
	}

	unknown, _ := domain.NewEveryone(ids.New[ids.GatewayKind](), "open", nil, nil)
	if err := repo.UpsertEveryone(ctx, unknown); !errors.Is(err, domain.ErrInvalidEveryone) {
		t.Fatalf("an unknown gateway must be a validation error, got %v", err)
	}
}

func TestEveryoneRepositoryPruneRegistry(t *testing.T) {
	ctx, pool := openEveryoneSchema(t)
	repo := NewEveryoneRepository(&database.Connection{Pool: pool}, nil)
	gw := insertGateway(t, ctx, pool)
	reg, other := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()

	mixed, _ := domain.NewEveryone(gw, "curated", []domain.EveryoneGrant{{CatalogCode: "github"}, {CatalogCode: "snowflake", RegistryID: reg}}, []string{"Contractors"})
	if err := repo.UpsertEveryone(ctx, mixed); err != nil {
		t.Fatalf("UpsertEveryone: %v", err)
	}
	if err := repo.PruneRegistry(ctx, gw, other); err != nil {
		t.Fatalf("an unrelated registry: %v", err)
	}
	if err := repo.PruneRegistry(ctx, gw, reg); err != nil {
		t.Fatalf("PruneRegistry: %v", err)
	}
	got, _ := repo.GetEveryone(ctx, gw)
	if got == nil || len(got.Grants) != 1 || got.Grants[0].CatalogCode != "github" || got.ExcludedGroups[0] != "Contractors" {
		t.Fatalf("only the deleted registry's grant goes, got %+v", got)
	}

	only, _ := domain.NewEveryone(gw, "curated", []domain.EveryoneGrant{{CatalogCode: "snowflake", RegistryID: reg}}, nil)
	if err := repo.UpsertEveryone(ctx, only); err != nil {
		t.Fatalf("UpsertEveryone: %v", err)
	}
	if err := repo.PruneRegistry(ctx, gw, reg); err != nil {
		t.Fatalf("PruneRegistry: %v", err)
	}
	if got, _ := repo.GetEveryone(ctx, gw); got != nil {
		t.Fatalf("a curated object left without grants is removed, got %+v", got)
	}
	if err := repo.PruneRegistry(ctx, gw, reg); err != nil {
		t.Fatalf("a gateway without Everyone is a no-op, got %v", err)
	}
}
