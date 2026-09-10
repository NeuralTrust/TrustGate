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
	"slices"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
)

func TestConsumer_PruneRegistry(t *testing.T) {
	t.Parallel()
	victim := ids.New[ids.RegistryKind]()
	keeper := ids.New[ids.RegistryKind]()

	tests := []struct {
		name          string
		consumer      func() *Consumer
		wantChanged   bool
		wantRewritten []string
		wantNulled    []string
		assert        func(t *testing.T, c *Consumer)
	}{
		{
			name: "no reference leaves the consumer untouched",
			consumer: func() *Consumer {
				return &Consumer{
					ModelPolicies: ModelPolicies{keeper: {Allowed: []string{"gpt-4o"}}},
					LBConfig:      &LBConfig{Enabled: true, Members: []LBPoolMember{{RegistryID: keeper}}},
				}
			},
			wantChanged: false,
			assert: func(t *testing.T, c *Consumer) {
				if _, ok := c.ModelPolicies[keeper]; !ok {
					t.Fatal("keeper policy was removed")
				}
				if c.LBConfig == nil || len(c.LBConfig.Members) != 1 {
					t.Fatalf("lb_config = %+v, want the keeper member", c.LBConfig)
				}
			},
		},
		{
			name: "model policy entry is removed",
			consumer: func() *Consumer {
				return &Consumer{
					ModelPolicies: ModelPolicies{
						victim: {Allowed: []string{"gpt-4.1-nano"}},
						keeper: {Allowed: []string{"gpt-4o"}},
					},
				}
			},
			wantChanged:   true,
			wantRewritten: []string{registry.PrunedModelPolicies},
			assert: func(t *testing.T, c *Consumer) {
				if _, ok := c.ModelPolicies[victim]; ok {
					t.Fatal("victim policy survived the prune")
				}
				if _, ok := c.ModelPolicies[keeper]; !ok {
					t.Fatal("keeper policy was removed")
				}
			},
		},
		{
			name: "only model policy leaves no empty map behind",
			consumer: func() *Consumer {
				return &Consumer{ModelPolicies: ModelPolicies{victim: {Allowed: []string{"gpt-4.1-nano"}}}}
			},
			wantChanged: true,
			wantNulled:  []string{registry.PrunedModelPolicies},
			assert: func(t *testing.T, c *Consumer) {
				if c.ModelPolicies != nil {
					t.Fatalf("ModelPolicies = %+v, want nil", c.ModelPolicies)
				}
			},
		},
		{
			name: "smart routing tier above the floor is dropped and the ladder survives",
			consumer: func() *Consumer {
				return &Consumer{
					ModelPolicies: ModelPolicies{
						victim: {Allowed: []string{"gpt-4.1-nano"}},
						keeper: {Allowed: []string{"gpt-4o"}},
					},
					LBConfig: &LBConfig{
						Enabled:   true,
						Algorithm: algorithm.SmartRouting,
						Members: []LBPoolMember{
							{RegistryID: keeper, Model: "gpt-4o"},
							{RegistryID: victim, Model: "gpt-4.1-nano"},
						},
						SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{
							{MinScore: 0, RegistryID: keeper, Model: "gpt-4o"},
							{MinScore: 0.5, RegistryID: victim, Model: "gpt-4.1-nano"},
						}},
					},
				}
			},
			wantChanged:   true,
			wantRewritten: []string{registry.PrunedModelPolicies, registry.PrunedLBConfig},
			assert: func(t *testing.T, c *Consumer) {
				if c.LBConfig == nil {
					t.Fatal("lb_config was dropped even though a member and the floor tier remain")
				}
				if len(c.LBConfig.Members) != 1 || c.LBConfig.Members[0].RegistryID != keeper {
					t.Fatalf("Members = %+v, want only the keeper", c.LBConfig.Members)
				}
				if c.LBConfig.Algorithm != algorithm.SmartRouting {
					t.Fatalf("Algorithm = %q, want it untouched", c.LBConfig.Algorithm)
				}
				if c.LBConfig.SmartRouting == nil || len(c.LBConfig.SmartRouting.Tiers) != 1 ||
					c.LBConfig.SmartRouting.Tiers[0].RegistryID != keeper {
					t.Fatalf("SmartRouting = %+v, want only the keeper tier", c.LBConfig.SmartRouting)
				}
			},
		},
		{
			name: "losing the cheapest tier drops the ladder instead of promoting its band",
			consumer: func() *Consumer {
				return &Consumer{
					ModelPolicies: ModelPolicies{
						victim: {Allowed: []string{"gpt-4.1-nano"}},
						keeper: {Allowed: []string{"gpt-4o"}},
					},
					LBConfig: &LBConfig{
						Enabled:   true,
						Algorithm: algorithm.SmartRouting,
						PoolAlias: "support-pool",
						Members: []LBPoolMember{
							{RegistryID: victim, Model: "gpt-4.1-nano"},
							{RegistryID: keeper, Model: "gpt-4o"},
						},
						SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{
							{MinScore: 0, RegistryID: victim, Model: "gpt-4.1-nano"},
							{MinScore: 0.6, RegistryID: keeper, Model: "gpt-4o"},
						}},
					},
				}
			},
			wantChanged:   true,
			wantRewritten: []string{registry.PrunedModelPolicies, registry.PrunedLBConfig},
			wantNulled:    []string{registry.PrunedSmartRouting},
			assert: func(t *testing.T, c *Consumer) {
				if c.LBConfig == nil {
					t.Fatal("lb_config was dropped, losing the surviving member and the pool alias")
				}
				if c.LBConfig.SmartRouting != nil {
					t.Fatalf("SmartRouting = %+v, want nil so no band is systematically promoted",
						c.LBConfig.SmartRouting)
				}
				if c.LBConfig.Algorithm != algorithm.RoundRobin {
					t.Fatalf("Algorithm = %q, want %q so the pool falls back uniformly",
						c.LBConfig.Algorithm, algorithm.RoundRobin)
				}
				if c.LBConfig.PoolAlias != "support-pool" {
					t.Fatalf("PoolAlias = %q, want it preserved", c.LBConfig.PoolAlias)
				}
				if len(c.LBConfig.Members) != 1 || c.LBConfig.Members[0].RegistryID != keeper {
					t.Fatalf("Members = %+v, want only the keeper", c.LBConfig.Members)
				}
			},
		},
		{
			name: "pool losing its last member drops lb_config",
			consumer: func() *Consumer {
				return &Consumer{
					ModelPolicies: ModelPolicies{victim: {Allowed: []string{"gpt-4.1-nano"}}},
					LBConfig: &LBConfig{
						Enabled: true,
						Members: []LBPoolMember{{RegistryID: victim}},
					},
				}
			},
			wantChanged: true,
			wantNulled:  []string{registry.PrunedModelPolicies, registry.PrunedLBConfig},
			assert: func(t *testing.T, c *Consumer) {
				if c.LBConfig != nil {
					t.Fatalf("LBConfig = %+v, want nil", c.LBConfig)
				}
			},
		},
		{
			name: "ladder losing its last tier keeps the pool and drops only the ladder",
			consumer: func() *Consumer {
				return &Consumer{
					ModelPolicies: ModelPolicies{
						victim: {Allowed: []string{"gpt-4.1-nano"}},
						keeper: {Allowed: []string{"gpt-4o"}},
					},
					LBConfig: &LBConfig{
						Enabled:   true,
						Algorithm: algorithm.SmartRouting,
						Members: []LBPoolMember{
							{RegistryID: keeper, Model: "gpt-4o"},
							{RegistryID: victim, Model: "gpt-4.1-nano"},
						},
						SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{
							{MinScore: 0, RegistryID: victim, Model: "gpt-4.1-nano"},
						}},
					},
				}
			},
			wantChanged:   true,
			wantRewritten: []string{registry.PrunedModelPolicies, registry.PrunedLBConfig},
			wantNulled:    []string{registry.PrunedSmartRouting},
			assert: func(t *testing.T, c *Consumer) {
				if c.LBConfig == nil {
					t.Fatal("LBConfig was dropped even though the keeper member remains")
				}
				if c.LBConfig.SmartRouting != nil {
					t.Fatalf("SmartRouting = %+v, want nil", c.LBConfig.SmartRouting)
				}
				if c.LBConfig.Algorithm != algorithm.RoundRobin {
					t.Fatalf("Algorithm = %q, want %q", c.LBConfig.Algorithm, algorithm.RoundRobin)
				}
			},
		},
		{
			name: "fallback step is dropped and the chain keeps its order",
			consumer: func() *Consumer {
				return &Consumer{
					Fallback: &Fallback{
						Enabled:  true,
						Triggers: []FallbackTrigger{TriggerHTTP5xx},
						Budget:   FallbackBudget{MaxAttempts: 3},
						Chain:    registry.Registries{victim, keeper},
					},
				}
			},
			wantChanged:   true,
			wantRewritten: []string{registry.PrunedFallback},
			assert: func(t *testing.T, c *Consumer) {
				if c.Fallback == nil {
					t.Fatal("fallback was dropped even though a step remains")
				}
				if len(c.Fallback.Chain) != 1 || c.Fallback.Chain[0] != keeper {
					t.Fatalf("Chain = %v, want [%s]", c.Fallback.Chain, keeper)
				}
			},
		},
		{
			name: "fallback losing its last step is dropped whole",
			consumer: func() *Consumer {
				return &Consumer{
					Fallback: &Fallback{
						Enabled:  true,
						Triggers: []FallbackTrigger{TriggerHTTP5xx},
						Budget:   FallbackBudget{MaxAttempts: 3},
						Chain:    registry.Registries{victim},
					},
				}
			},
			wantChanged: true,
			wantNulled:  []string{registry.PrunedFallback},
			assert: func(t *testing.T, c *Consumer) {
				if c.Fallback != nil {
					t.Fatalf("Fallback = %+v, want nil", c.Fallback)
				}
			},
		},
		{
			name: "toolkit entries for the registry are dropped",
			consumer: func() *Consumer {
				return &Consumer{
					Type: TypeMCP,
					MCP: &MCPPolicy{
						FailMode: FailModeClosed,
						Toolkit: Toolkit{
							{RegistryID: victim, Tool: ToolWildcard},
							{RegistryID: keeper, Tool: ToolWildcard},
						},
					},
				}
			},
			wantChanged:   true,
			wantRewritten: []string{registry.PrunedToolkit},
			assert: func(t *testing.T, c *Consumer) {
				if len(c.MCP.Toolkit) != 1 || c.MCP.Toolkit[0].RegistryID != keeper {
					t.Fatalf("Toolkit = %+v, want only the keeper entry", c.MCP.Toolkit)
				}
				if c.MCP.FailMode != FailModeClosed {
					t.Fatalf("FailMode = %q, want it preserved", c.MCP.FailMode)
				}
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := tc.consumer()
			c.ID = ids.New[ids.ConsumerKind]()
			prune, changed := c.PruneRegistry(victim)
			if changed != tc.wantChanged {
				t.Fatalf("PruneRegistry() changed = %v, want %v", changed, tc.wantChanged)
			}
			if changed && prune.ConsumerID != c.ID {
				t.Fatalf("ConsumerID = %s, want %s", prune.ConsumerID, c.ID)
			}
			if !slices.Equal(prune.Rewritten, tc.wantRewritten) {
				t.Fatalf("Rewritten = %v, want %v", prune.Rewritten, tc.wantRewritten)
			}
			if !slices.Equal(prune.Nulled, tc.wantNulled) {
				t.Fatalf("Nulled = %v, want %v", prune.Nulled, tc.wantNulled)
			}
			tc.assert(t, c)
		})
	}
}

func TestConsumer_PruneRegistryLeavesAValidatableConsumer(t *testing.T) {
	t.Parallel()
	victim := ids.New[ids.RegistryKind]()
	keeper := ids.New[ids.RegistryKind]()
	c, err := New(CreateParams{
		GatewayID:   ids.New[ids.GatewayKind](),
		Name:        "smart-router",
		Type:        TypeLLM,
		RegistryIDs: []ids.RegistryID{keeper, victim},
		ModelPolicies: ModelPolicies{
			keeper: {Allowed: []string{"gpt-4o"}},
			victim: {Allowed: []string{"gpt-4.1-nano"}},
		},
		LBConfig: &LBConfig{
			Enabled:   true,
			Algorithm: algorithm.SmartRouting,
			Members: []LBPoolMember{
				{RegistryID: victim, Model: "gpt-4.1-nano"},
				{RegistryID: keeper, Model: "gpt-4o"},
			},
			SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{
				{MinScore: 0, RegistryID: victim, Model: "gpt-4.1-nano"},
				{MinScore: 0.6, RegistryID: keeper, Model: "gpt-4o"},
			}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, changed := c.PruneRegistry(victim); !changed {
		t.Fatal("PruneRegistry() changed = false, want the victim references removed")
	}
	c.RegistryIDs = []ids.RegistryID{keeper}

	if err := c.Validate(); err != nil {
		t.Fatalf("Validate after prune: %v", err)
	}
	if c.LBConfig == nil || c.LBConfig.SmartRouting != nil {
		t.Fatalf("LBConfig = %+v, want the pool kept and the ladder dropped", c.LBConfig)
	}
	if c.LBConfig.Algorithm != algorithm.RoundRobin {
		t.Fatalf("Algorithm = %q, want %q", c.LBConfig.Algorithm, algorithm.RoundRobin)
	}
}

func TestConsumer_PruneRegistryIgnoresNilRegistry(t *testing.T) {
	t.Parallel()
	c := &Consumer{ModelPolicies: ModelPolicies{ids.New[ids.RegistryKind](): {}}}
	if _, changed := c.PruneRegistry(ids.RegistryID{}); changed {
		t.Fatal("PruneRegistry(nil) changed = true, want false")
	}
}
