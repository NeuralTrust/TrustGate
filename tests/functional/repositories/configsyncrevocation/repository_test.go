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

package configsyncrevocation_test

import (
	"context"
	"os"
	"sort"
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsyncrevocation"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setup(t *testing.T) *repo.Repository {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping config-sync revocation repository integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PG_TEST_URL: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open pgxpool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping: %v", err)
	}
	if err := database.NewMigrationsManager(pool).ApplyPending(ctx); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	const truncate = "TRUNCATE TABLE config_sync_token_revocations, config_sync_scope_issued_before"
	if _, err := pool.Exec(ctx, truncate); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), truncate)
		pool.Close()
	})
	return repo.NewRepository(&database.Connection{Pool: pool})
}

func load(t *testing.T, r *repo.Repository) domain.Revocations {
	t.Helper()
	got, err := r.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	sort.Slice(got.JTIs, func(i, j int) bool {
		if got.JTIs[i].Scope != got.JTIs[j].Scope {
			return got.JTIs[i].Scope < got.JTIs[j].Scope
		}
		return got.JTIs[i].JTI < got.JTIs[j].JTI
	})
	sort.Slice(got.Marks, func(i, j int) bool { return got.Marks[i].Scope < got.Marks[j].Scope })
	return got
}

func apply(t *testing.T, r *repo.Repository, rev domain.Revocation) {
	t.Helper()
	if err := r.Apply(context.Background(), rev); err != nil {
		t.Fatalf("Apply(%+v): %v", rev, err)
	}
}

func TestRepository_ApplyIsIdempotent(t *testing.T) {
	r := setup(t)
	rev := domain.Revocation{Scope: "gw", JTIs: []string{"a1"}, IssuedBefore: 1000}

	apply(t, r, rev)
	apply(t, r, rev)

	got := load(t, r)
	if len(got.JTIs) != 1 || got.JTIs[0] != (domain.JTIRevocation{Scope: "gw", JTI: "a1"}) {
		t.Fatalf("JTIs after a repeated Apply = %+v, want one row for gw/a1", got.JTIs)
	}
	if len(got.Marks) != 1 || got.Marks[0] != (domain.IssuedBeforeMark{Scope: "gw", IssuedBefore: 1000}) {
		t.Fatalf("Marks after a repeated Apply = %+v, want one mark of 1000 for gw", got.Marks)
	}
}

func TestRepository_DuplicateJTIsInOneRequest(t *testing.T) {
	r := setup(t)

	apply(t, r, domain.Revocation{Scope: "gw", JTIs: []string{"a1", "a1", "b2"}})

	got := load(t, r)
	want := []domain.JTIRevocation{{Scope: "gw", JTI: "a1"}, {Scope: "gw", JTI: "b2"}}
	if len(got.JTIs) != len(want) {
		t.Fatalf("JTIs = %+v, want %+v", got.JTIs, want)
	}
	for i := range want {
		if got.JTIs[i] != want[i] {
			t.Fatalf("JTIs = %+v, want %+v", got.JTIs, want)
		}
	}
}

func TestRepository_MarkNeverLowers(t *testing.T) {
	r := setup(t)

	apply(t, r, domain.Revocation{Scope: "gw", IssuedBefore: 1000})
	apply(t, r, domain.Revocation{Scope: "gw", IssuedBefore: 900})
	if got := load(t, r).Marks; len(got) != 1 || got[0].IssuedBefore != 1000 {
		t.Fatalf("a lower mark moved the stored value: %+v", got)
	}

	apply(t, r, domain.Revocation{Scope: "gw", IssuedBefore: 1200})
	if got := load(t, r).Marks; len(got) != 1 || got[0].IssuedBefore != 1200 {
		t.Fatalf("a higher mark did not replace the stored value: %+v", got)
	}
}

func TestRepository_LoadReturnsBothTables(t *testing.T) {
	r := setup(t)

	apply(t, r, domain.Revocation{Scope: "gw1", JTIs: []string{"a1"}, IssuedBefore: 500})
	apply(t, r, domain.Revocation{Scope: "gw2", JTIs: []string{"a1"}})

	got := load(t, r)
	wantJTIs := []domain.JTIRevocation{{Scope: "gw1", JTI: "a1"}, {Scope: "gw2", JTI: "a1"}}
	if len(got.JTIs) != len(wantJTIs) {
		t.Fatalf("JTIs = %+v, want %+v", got.JTIs, wantJTIs)
	}
	for i := range wantJTIs {
		if got.JTIs[i] != wantJTIs[i] {
			t.Fatalf("JTIs = %+v, want %+v", got.JTIs, wantJTIs)
		}
	}
	if len(got.Marks) != 1 || got.Marks[0] != (domain.IssuedBeforeMark{Scope: "gw1", IssuedBefore: 500}) {
		t.Fatalf("Marks = %+v, want one mark of 500 for gw1", got.Marks)
	}
}
