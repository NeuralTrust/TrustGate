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
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type seededRow struct {
	tier                 string
	burst, quota, maxIns int
}

func TestTenantEntitlementsSeed(t *testing.T) {
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	// Temp tables shadow the real ones for this transaction only.
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE gateways (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			metadata JSONB,
			entitlements JSONB,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		) ON COMMIT DROP;
		CREATE TEMP TABLE tenant_entitlements (
			tenant_id TEXT PRIMARY KEY, tier TEXT NOT NULL,
			burst_per_min INTEGER NOT NULL, quota_per_month INTEGER NOT NULL,
			max_instances INTEGER NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		) ON COMMIT DROP;
		SET LOCAL search_path TO pg_temp`); err != nil {
		t.Fatalf("setup: %v", err)
	}

	add := func(tenant, entitlements string) {
		t.Helper()
		meta := `{}`
		if tenant != "" {
			meta = `{"tenant_id":"` + tenant + `"}`
		}
		if _, err := tx.Exec(ctx, `INSERT INTO gateways (metadata, entitlements) VALUES ($1::jsonb, $2::jsonb)`, meta, entitlements); err != nil {
			t.Fatalf("insert gateway: %v", err)
		}
	}
	// agree: two gateways with the same plan.
	add("agree", `{"tier":"standard","burst_per_min":300,"quota_per_month":100000,"max_instances":5}`)
	add("agree", `{"tier":"standard","burst_per_min":300,"quota_per_month":100000,"max_instances":5}`)
	// differ: the largest of each cap wins, and 0 (unlimited) is the largest.
	add("differ", `{"tier":"free","burst_per_min":60,"quota_per_month":10000,"max_instances":5}`)
	add("differ", `{"tier":"enterprise","burst_per_min":1000,"quota_per_month":0,"max_instances":3}`)
	add("differ", `{"tier":"standard","burst_per_min":300,"quota_per_month":100000,"max_instances":9}`)
	// A stale, renamed sibling must not win by being the newest row.
	if _, err := tx.Exec(ctx, `UPDATE gateways SET updated_at = now() + interval '1 day' WHERE entitlements->>'tier' = 'free'`); err != nil {
		t.Fatalf("touch: %v", err)
	}
	// Unusable stamps must be skipped, not abort the migration.
	add("huge", `{"tier":"free","burst_per_min":60,"quota_per_month":3000000000,"max_instances":5}`)
	add("fraction", `{"tier":"free","burst_per_min":60.5,"quota_per_month":10,"max_instances":5}`)
	add("text", `{"tier":"free","burst_per_min":"60","quota_per_month":10,"max_instances":5}`)
	add("partial", `{"tier":"free","burst_per_min":60}`)
	add("negative", `{"tier":"free","burst_per_min":60,"quota_per_month":-1,"max_instances":5}`)
	// The domain rejects a burst of 0 and the limiter would answer 429 to every
	// request, so the seed must not store it.
	add("zeroburst", `{"tier":"free","burst_per_min":0,"quota_per_month":1000,"max_instances":5}`)
	// A usable gateway beside an unusable one still seeds its tenant.
	add("mixed", `{"tier":"free","burst_per_min":60,"quota_per_month":10000,"max_instances":5}`)
	add("mixed", `{"tier":"free","burst_per_min":60,"quota_per_month":3000000000,"max_instances":5}`)
	// No tenant, and no stamp at all.
	add("", `{"tier":"free","burst_per_min":60,"quota_per_month":10000,"max_instances":5}`)
	add("unstamped", `{"tier":"free"}`)
	// A row that already exists is never overwritten.
	if _, err := tx.Exec(ctx, `INSERT INTO tenant_entitlements (tenant_id, tier, burst_per_min, quota_per_month, max_instances) VALUES ('agree','enterprise',1,1,1)`); err != nil {
		t.Fatalf("preexisting: %v", err)
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	if err := seedTenantEntitlementsFromGateways(ctx, tx, logger); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rows, err := tx.Query(ctx, `SELECT tenant_id, tier, burst_per_min, quota_per_month, max_instances FROM tenant_entitlements`)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := map[string]seededRow{}
	for rows.Next() {
		var id string
		var r seededRow
		if err := rows.Scan(&id, &r.tier, &r.burst, &r.quota, &r.maxIns); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[id] = r
	}
	rows.Close()

	want := map[string]seededRow{
		"agree":  {"enterprise", 1, 1, 1}, // pre-existing row kept
		"differ": {"enterprise", 1000, 0, 9},
		"mixed":  {"free", 60, 10000, 5},
	}
	if len(got) != len(want) {
		t.Fatalf("seeded tenants = %v, want exactly %v", got, want)
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("tenant %s = %+v, want %+v", id, got[id], w)
		}
	}

	out := logs.String()
	if !strings.Contains(out, "differ") || !strings.Contains(out, "carried different stamped caps") {
		t.Errorf("the disagreement was not logged: %s", out)
	}
	for _, id := range []string{"huge", "fraction", "text", "partial", "negative", "zeroburst", "mixed"} {
		if !strings.Contains(out, id) {
			t.Errorf("skipped tenant %q was not named in the warning: %s", id, out)
		}
	}
	if strings.Contains(out, "unstamped") {
		t.Errorf("a gateway with no caps at all is not a skipped stamp: %s", out)
	}
}
