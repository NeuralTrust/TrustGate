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
	"encoding/json"
	"fmt"
	"testing"
)

func TestLegacyFollowupMigrationUpIdempotentDown(t *testing.T) {
	ctx, tx := smartRoutingMigrationFixture(t)
	if err := upCanonicalizeSmartRouting(ctx, tx); err != nil {
		t.Fatal(err)
	}
	const one = "33333333-3333-3333-3333-333333333333"
	const four = "44444444-4444-4444-4444-444444444444"
	originals := map[string][]byte{}
	for id, n := range map[string]int{one: 1, four: 4} {
		members, tiers := []map[string]any{}, []map[string]any{}
		models := []string{}
		for i, cut := range []float64{.72, .12, .97, .34}[:n] {
			model := fmt.Sprintf("model-%d", i)
			members = append(members, map[string]any{"registry_id": migrationRegistry, "model": model, "extension": "kept"})
			tiers = append(tiers, map[string]any{"registry_id": migrationRegistry, "model": model, "min_score": cut, "extension": "kept"})
			models = append(models, model)
		}
		raw := migrationTestJSON(t, map[string]any{"enabled": false, "algorithm": "smart-routing", "extension": "kept",
			"members": members, "smart_routing": map[string]any{"tiers": tiers}})
		policies := migrationTestJSON(t, map[string]any{migrationRegistry: map[string]any{"allowed": models}})
		if _, err := tx.Exec(ctx, `INSERT INTO consumers (id,gateway_id,lb_config,model_policies) VALUES ($1::uuid,$2::uuid,$3::jsonb,$4::jsonb)`, id, migrationGateway, raw, policies); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO consumer_registry VALUES ($1::uuid,$2::uuid)`, id, migrationRegistry); err != nil {
			t.Fatal(err)
		}
		originals[id] = migrationStoredLB(t, ctx, tx, id)
	}
	if err := upPreserveLegacySmartRouting(ctx, tx); err != nil {
		t.Fatal(err)
	}
	for id, original := range originals {
		migrated := migrationStoredLB(t, ctx, tx, id)
		if equalRoutingJSON(original, migrated) {
			t.Fatal("follow-up did not translate stored legacy JSON")
		}
		var fields map[string]any
		if err := json.Unmarshal(migrated, &fields); err != nil {
			t.Fatal(err)
		}
		if id == one && (fields["algorithm"] != "round-robin" || fields["smart_routing"] != nil) {
			t.Fatal("single stored route was not fixed")
		}
		if id == four {
			smart := fields["smart_routing"].(map[string]any)
			if smart["legacy_thresholds"] != true || len(smart["tiers"].([]any)) != 4 {
				t.Fatal("legacy routes were not retained")
			}
			for i, cut := range []float64{.72, .12, .97, .34} {
				tier := smart["tiers"].([]any)[i].(map[string]any)
				if tier["min_score"] != cut || tier["extension"] != "kept" {
					t.Fatal("stored threshold/order/extension changed")
				}
			}
		}
		var backup []byte
		if err := tx.QueryRow(ctx, `SELECT lb_config_before FROM sr1_legacy_routing_migration_backup WHERE consumer_id=$1::uuid`, id).Scan(&backup); err != nil || !equalRoutingJSON(original, backup) {
			t.Fatalf("exact legacy backup not retained: %v", err)
		}
	}
	if err := upPreserveLegacySmartRouting(ctx, tx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sr1_legacy_routing_migration_backup`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("idempotent backup=%d err=%v", count, err)
	}
	if err := downPreserveLegacySmartRouting(ctx, tx); err != nil {
		t.Fatal(err)
	}
	for id, original := range originals {
		if !equalRoutingJSON(original, migrationStoredLB(t, ctx, tx, id)) {
			t.Fatal("follow-up rollback did not restore exact legacy JSON")
		}
	}
	if err := downPreserveLegacySmartRouting(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := upPreserveLegacySmartRouting(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE consumers SET updated_at=updated_at+INTERVAL '1 second' WHERE id=$1::uuid`, one); err != nil {
		t.Fatal(err)
	}
	canonical := migrationStoredLB(t, ctx, tx, four)
	if err := downPreserveLegacySmartRouting(ctx, tx); err == nil {
		t.Fatal("follow-up rollback overwrote later owner edit")
	}
	if !equalRoutingJSON(canonical, migrationStoredLB(t, ctx, tx, four)) {
		t.Fatal("rollback partially restored before detecting conflict")
	}
}

func TestLegacyFollowupPreflightWritesNothing(t *testing.T) {
	ctx, tx := smartRoutingMigrationFixture(t)
	if _, err := tx.Exec(ctx, `UPDATE consumers SET lb_config=jsonb_set(lb_config,'{smart_routing,tiers}','[]'::jsonb) WHERE id=$1::uuid`, migrationConsumerTwo); err != nil {
		t.Fatal(err)
	}
	before := migrationStoredLB(t, ctx, tx, migrationConsumerOne)
	if err := upPreserveLegacySmartRouting(ctx, tx); err == nil {
		t.Fatal("unresolved candidate accepted")
	}
	if !equalRoutingJSON(before, migrationStoredLB(t, ctx, tx, migrationConsumerOne)) {
		t.Fatal("valid consumer was partially migrated")
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('sr1_legacy_routing_migration_backup') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("backup DDL ran before complete preflight: %v", err)
	}
}
