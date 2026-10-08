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
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/modelmatch"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20261007120000_canonicalize_smart_routing",
		Name: "preflight and back up canonical session routing configurations",
		Up:   upCanonicalizeSmartRouting,
		Down: downCanonicalizeSmartRouting,
	})
}

type smartRoutingMigrationRow struct {
	id            string
	before, after []byte
	updatedAt     time.Time
}

func upCanonicalizeSmartRouting(ctx context.Context, tx pgx.Tx) error {
	return upSmartRoutingMigration(ctx, tx, "sr1_routing_migration_backup")
}

func upSmartRoutingMigration(ctx context.Context, tx pgx.Tx, backupTable string) error {
	if _, err := tx.Exec(ctx, `LOCK TABLE consumers, consumer_registry, registries IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("lock smart-routing preflight: %w", err)
	}
	rows, err := tx.Query(ctx, `
		SELECT c.id::text, c.lb_config, COALESCE(c.model_policies, '{}'::jsonb), c.updated_at,
		       COALESCE((SELECT jsonb_agg(r.id::text ORDER BY r.id)
		                   FROM registries r
		                  WHERE r.gateway_id = c.gateway_id
		                    AND (EXISTS (SELECT 1 FROM consumer_registry cr
		                                  WHERE cr.consumer_id = c.id AND cr.registry_id = r.id)
		                         OR COALESCE(c.fallback->'chain', '[]'::jsonb) ? r.id::text)), '[]'::jsonb)
		  FROM consumers c
		 WHERE c.lb_config IS NOT NULL
		   AND (c.lb_config->>'algorithm' = 'smart-routing' OR c.lb_config ? 'smart_routing')
		 ORDER BY c.id
		 FOR UPDATE OF c`)
	if err != nil {
		return fmt.Errorf("read smart-routing preflight: %w", err)
	}
	plans := make([]smartRoutingMigrationRow, 0)
	problems := make([]string, 0)
	for rows.Next() {
		var plan smartRoutingMigrationRow
		var policiesRaw, knownRaw []byte
		if err := rows.Scan(&plan.id, &plan.before, &policiesRaw, &plan.updatedAt, &knownRaw); err != nil {
			rows.Close()
			return fmt.Errorf("scan smart-routing preflight: %w", err)
		}
		var knownIDs []ids.RegistryID
		if err := json.Unmarshal(knownRaw, &knownIDs); err != nil {
			rows.Close()
			return fmt.Errorf("decode smart-routing references: %w", err)
		}
		known := make(map[ids.RegistryID]struct{}, len(knownIDs))
		for _, id := range knownIDs {
			known[id] = struct{}{}
		}
		plan.after, err = canonicalSmartRoutingJSON(plan.before, policiesRaw, known)
		if err != nil {
			problems = append(problems, fmt.Sprintf("consumer %s: %s", plan.id, err))
			continue
		}
		if !equalRoutingJSON(plan.before, plan.after) {
			plans = append(plans, plan)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate smart-routing preflight: %w", err)
	}
	if len(problems) != 0 {
		return fmt.Errorf("smart-routing preflight rejected %d consumers; no configurations written: %s", len(problems), strings.Join(problems, "; "))
	}
	backup := pgx.Identifier{backupTable}.Sanitize()
	if _, err := tx.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			consumer_id UUID PRIMARY KEY,
			lb_config_before JSONB NOT NULL,
			lb_config_after JSONB NOT NULL,
			updated_at_before TIMESTAMPTZ NOT NULL,
			updated_at_after TIMESTAMPTZ NOT NULL
		)`, backup)); err != nil {
		return fmt.Errorf("create smart-routing backup: %w", err)
	}
	for _, plan := range plans {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO %s
			    (consumer_id, lb_config_before, lb_config_after, updated_at_before, updated_at_after)
			VALUES ($1::uuid, $2::jsonb, $3::jsonb, $4, NOW())`, backup), plan.id, plan.before, plan.after, plan.updatedAt); err != nil {
			return fmt.Errorf("back up consumer %s: %w", plan.id, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE consumers SET lb_config = $2::jsonb, updated_at = NOW() WHERE id = $1::uuid`, plan.id, plan.after); err != nil {
			return fmt.Errorf("canonicalize consumer %s: %w", plan.id, err)
		}
	}
	return nil
}

func downCanonicalizeSmartRouting(ctx context.Context, tx pgx.Tx) error {
	return downSmartRoutingMigration(ctx, tx, "sr1_routing_migration_backup")
}

func downSmartRoutingMigration(ctx context.Context, tx pgx.Tx, backupTable string) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, backupTable).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	backup := pgx.Identifier{backupTable}.Sanitize()
	if _, err := tx.Exec(ctx, fmt.Sprintf(`LOCK TABLE consumers, %s IN SHARE ROW EXCLUSIVE MODE`, backup)); err != nil {
		return err
	}
	var conflicts int
	if err := tx.QueryRow(ctx, fmt.Sprintf(`
		SELECT count(*) FROM %s b
		LEFT JOIN consumers c ON c.id = b.consumer_id
		WHERE c.id IS NULL OR c.lb_config IS DISTINCT FROM b.lb_config_after
		   OR c.updated_at IS DISTINCT FROM b.updated_at_after`, backup)).Scan(&conflicts); err != nil {
		return err
	}
	if conflicts != 0 {
		return fmt.Errorf("cannot restore smart-routing backup: %d consumers changed or were deleted", conflicts)
	}
	_, err := tx.Exec(ctx, fmt.Sprintf(`
		UPDATE consumers c SET lb_config = b.lb_config_before, updated_at = b.updated_at_before
		FROM %s b WHERE c.id = b.consumer_id;
		DROP TABLE %s`, backup, backup))
	return err
}

func canonicalSmartRoutingJSON(raw, policiesRaw []byte, known map[ids.RegistryID]struct{}) ([]byte, error) {
	var config consumer.LBConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, err
	}
	if config.SmartRouting == nil {
		if config.Algorithm == algorithm.SmartRouting {
			return nil, fmt.Errorf("smart_routing is required")
		}
		return raw, nil
	}
	if config.Algorithm != algorithm.SmartRouting {
		return nil, fmt.Errorf("smart_routing requires the smart-routing algorithm")
	}
	var policies consumer.ModelPolicies
	if err := json.Unmarshal(policiesRaw, &policies); err != nil {
		return nil, err
	}
	tiers := config.SmartRouting.Tiers
	if len(tiers) == 0 {
		return nil, fmt.Errorf("requires at least one tier")
	}
	legacy := config.SmartRouting.SR1 == nil
	if len(tiers) == 1 && !legacy {
		return nil, fmt.Errorf("a single committed rung is not a valid stored ladder")
	}
	if legacy {
		config.SmartRouting.LegacyThresholds = len(tiers) > 3
	}
	scores := make([]float64, len(tiers))
	for i, tier := range tiers {
		if math.IsNaN(tier.MinScore) || math.IsInf(tier.MinScore, 0) || tier.MinScore < 0 || tier.MinScore > 1 {
			return nil, fmt.Errorf("tiers[%d].min_score must be in [0,1]", i)
		}
		scores[i] = tier.MinScore
	}
	sort.Float64s(scores)
	for i := 1; i < len(scores); i++ {
		if scores[i] == scores[i-1] {
			return nil, fmt.Errorf("tier thresholds must be distinct")
		}
	}
	for i, tier := range tiers {
		if tier.RouteModel() == "" {
			memberIndex := -1
			for j, member := range config.Members {
				if member.RegistryID != tier.RegistryID {
					continue
				}
				if memberIndex >= 0 {
					return nil, fmt.Errorf("tiers[%d] has ambiguous member routes", i)
				}
				memberIndex = j
			}
			if memberIndex < 0 {
				return nil, fmt.Errorf("tiers[%d] has no pool member", i)
			}
			model := migrationDeclaredModel(config.Members[memberIndex], policies[tier.RegistryID])
			if model == "" {
				return nil, fmt.Errorf("tiers[%d] needs an unambiguous concrete model", i)
			}
			config.SmartRouting.Tiers[i].Model = model
		}
		for j, member := range config.Members {
			if member.RegistryID == tier.RegistryID && member.RouteModel() == "" && migrationDeclaredModel(member, policies[tier.RegistryID]) == config.SmartRouting.Tiers[i].RouteModel() {
				config.Members[j].Model = config.SmartRouting.Tiers[i].Model
			}
		}
		if legacy && (len(tiers) == 2 || len(tiers) == 3) && !config.SmartRouting.LegacyThresholds {
			cuts := []float64{0, .45}
			if len(tiers) == 3 {
				cuts = []float64{0, .187, .45}
			}
			config.SmartRouting.Tiers[i].MinScore = cuts[sort.SearchFloat64s(scores, tier.MinScore)]
		}
	}
	if len(tiers) == 1 {
		return canonicalSingleRoutingJSON(raw, config, policies, known)
	}
	var lbFields, smartFields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &lbFields); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(lbFields["smart_routing"], &smartFields); err != nil {
		return nil, err
	}
	if legacy {
		for name := range smartFields {
			if strings.EqualFold(name, "legacy_thresholds") {
				delete(smartFields, name)
			}
		}
		config.SmartRouting.SR1 = &registry.SR1Config{CacheTTLSeconds: 300}
	} else {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(smartFields["sr1"], &fields); err != nil {
			return nil, err
		}
		flag := true
		seen := make(map[string]bool, 2)
		for name, value := range fields {
			key := strings.ToLower(name)
			if key == "escape_hatch_enabled" || key == "cache_ttl_seconds" {
				if seen[key] {
					return nil, fmt.Errorf("duplicate case-insensitive %s fields", key)
				}
				seen[key] = true
			}
			if !strings.EqualFold(name, "escape_hatch_enabled") {
				continue
			}
			if strings.TrimSpace(string(value)) == "null" {
				return nil, fmt.Errorf("escape_hatch_enabled must be a boolean")
			}
			if err := json.Unmarshal(value, &flag); err != nil {
				return nil, fmt.Errorf("escape_hatch_enabled must be a boolean: %w", err)
			}
		}
		config.SmartRouting.SR1.EscapeHatchEnabled = flag
	}
	if err := policies.Validate(known); err != nil {
		return nil, err
	}
	validation := config
	validation.Enabled = true
	if err := validation.ValidateTierRegistries(known); err != nil {
		return nil, err
	}
	if err := validation.Validate(policies); err != nil {
		return nil, err
	}
	var tierFields, memberFields []map[string]json.RawMessage
	if err := json.Unmarshal(smartFields["tiers"], &tierFields); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(lbFields["members"], &memberFields); err != nil {
		return nil, err
	}
	var sr1Fields map[string]json.RawMessage
	if !legacy {
		if err := json.Unmarshal(smartFields["sr1"], &sr1Fields); err != nil {
			return nil, err
		}
	}
	if sr1Fields == nil {
		sr1Fields = make(map[string]json.RawMessage)
	}
	for name := range sr1Fields {
		if strings.EqualFold(name, "escape_hatch_enabled") || strings.EqualFold(name, "cache_ttl_seconds") {
			delete(sr1Fields, name)
		}
	}
	type update struct {
		fields map[string]json.RawMessage
		name   string
		value  any
	}
	updates := []update{{sr1Fields, "cache_ttl_seconds", config.SmartRouting.SR1.CacheTTLSeconds}, {sr1Fields, "escape_hatch_enabled", config.SmartRouting.SR1.EscapeHatchEnabled}}
	if config.SmartRouting.LegacyThresholds {
		updates = append(updates, update{smartFields, "legacy_thresholds", true})
	}
	for i, tier := range config.SmartRouting.Tiers {
		updates = append(updates, update{tierFields[i], "min_score", tier.MinScore}, update{tierFields[i], "model", tier.Model})
	}
	for i, member := range config.Members {
		if member.Model != "" {
			updates = append(updates, update{memberFields[i], "model", member.Model})
		}
	}
	updates = append(updates, update{smartFields, "tiers", tierFields}, update{smartFields, "sr1", sr1Fields}, update{lbFields, "members", memberFields}, update{lbFields, "smart_routing", smartFields})
	for _, item := range updates {
		encoded, err := json.Marshal(item.value)
		if err != nil {
			return nil, fmt.Errorf("encode canonical %s: %w", item.name, err)
		}
		item.fields[item.name] = encoded
	}
	return json.Marshal(lbFields)
}

func migrationDeclaredModel(member consumer.LBPoolMember, policy consumer.ModelPolicy) string {
	model := member.RouteModel()
	if model == "" {
		candidate := strings.TrimSpace(policy.Default)
		if candidate != "" && (len(member.Models) == 0 || slices.Contains(member.Models, candidate)) {
			model = candidate
		} else if len(member.Models) == 1 {
			model = member.Models[0]
		}
	}
	if model == "" || modelmatch.IsPattern(model) {
		return ""
	}
	if len(policy.Allowed) > 0 {
		if _, allowed := modelmatch.MatchAny(model, policy.Allowed); !allowed {
			return ""
		}
	}
	return model
}

func equalRoutingJSON(a, b []byte) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}
