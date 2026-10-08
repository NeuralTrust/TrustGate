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

package consumer

import (
	"context"
	"errors"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestLegacyRoutingWriteRequiresStoredProvenance(t *testing.T) {
	id := ids.New[ids.RegistryKind]()
	previous := &domain.LBConfig{SmartRouting: &registry.SmartRoutingConfig{LegacyThresholds: true, Tiers: []registry.SmartRoutingTier{
		{RegistryID: id, Model: "low", MinScore: .2}, {RegistryID: id, Model: "high", MinScore: .8},
	}}}
	copyConfig := func() *domain.LBConfig {
		return &domain.LBConfig{SmartRouting: &registry.SmartRoutingConfig{Tiers: append([]registry.SmartRoutingTier(nil), previous.SmartRouting.Tiers...)}}
	}
	next := copyConfig()
	next.SmartRouting.Tiers[0], next.SmartRouting.Tiers[1] = next.SmartRouting.Tiers[1], next.SmartRouting.Tiers[0]
	if err := validateLegacyRoutingWrite(next, previous); err != nil || !next.SmartRouting.LegacyThresholds {
		t.Fatalf("omitted marker not inherited for the same routes/cuts: %v", err)
	}
	for _, change := range []func(*domain.LBConfig){
		func(c *domain.LBConfig) { c.SmartRouting.Tiers[0].MinScore = .1 },
		func(c *domain.LBConfig) { c.SmartRouting.Tiers[0].Model = "other" },
		func(c *domain.LBConfig) { c.SmartRouting.Tiers = c.SmartRouting.Tiers[:1] },
	} {
		next := copyConfig()
		change(next)
		if !errors.Is(validateLegacyRoutingWrite(next, previous), domain.ErrInvalidLBConfig) {
			t.Fatal("client rewrote a migration-only ladder")
		}
	}
	next = copyConfig()
	next.SmartRouting.LegacyThresholds = true
	if !errors.Is(validateLegacyRoutingWrite(next, nil), domain.ErrInvalidLBConfig) {
		t.Fatal("client forged migration provenance")
	}
	if _, err := (&creator{}).Create(context.Background(), CreateInput{LBConfig: next}); !errors.Is(err, domain.ErrInvalidLBConfig) {
		t.Fatalf("creation did not reject provenance before persistence: %v", err)
	}
}

func TestCreatorRejectsUnmarkedRetainedCutsEvenWhenDisabled(t *testing.T) {
	gw, id := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	for _, enabled := range []bool{false, true} {
		for _, n := range []int{2, 4} {
			cfg := &domain.LBConfig{Enabled: enabled, Algorithm: "smart-routing", SmartRouting: &registry.SmartRoutingConfig{SR1: &registry.SR1Config{CacheTTLSeconds: 300}}}
			policy := domain.ModelPolicy{}
			for i := 0; i < n; i++ {
				model := string(rune('a' + i))
				cfg.Members = append(cfg.Members, domain.LBPoolMember{RegistryID: id, Model: model})
				cfg.SmartRouting.Tiers = append(cfg.SmartRouting.Tiers, registry.SmartRoutingTier{RegistryID: id, Model: model, MinScore: .1 * float64(i+1)})
				policy.Allowed = append(policy.Allowed, model)
			}
			_, err := (&creator{}).Create(context.Background(), CreateInput{GatewayID: gw, Name: "custom", Type: domain.TypeLLM, RegistryIDs: []ids.RegistryID{id}, ModelPolicies: domain.ModelPolicies{id: policy}, LBConfig: cfg})
			if !errors.Is(err, domain.ErrInvalidLBConfig) {
				t.Fatalf("enabled=%t n=%d creation bypassed fixed-cut validation: %v", enabled, n, err)
			}
		}
	}
}
