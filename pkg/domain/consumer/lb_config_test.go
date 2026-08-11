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
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
)

func TestLBConfig_Validate(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	policies := ModelPolicies{
		registryID: {Allowed: []string{"gpt-4o"}},
	}
	tests := []struct {
		name   string
		config *LBConfig
	}{
		{
			name: "member outside policy",
			config: &LBConfig{
				Enabled: true,
				Members: []LBPoolMember{
					{RegistryID: ids.New[ids.RegistryKind](), Models: []string{"gpt-4o"}},
				},
			},
		},
		{
			name: "semantic without embedding",
			config: &LBConfig{
				Enabled:   true,
				Algorithm: "semantic",
				Members: []LBPoolMember{
					{RegistryID: registryID, Models: []string{"gpt-4o"}},
				},
			},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.config.Validate(policies)
			if !errors.Is(err, ErrInvalidLBConfig) {
				t.Fatalf("err = %v, want ErrInvalidLBConfig", err)
			}
		})
	}
}

func TestLBConfig_ValidateRouteIdentity(t *testing.T) {
	t.Parallel()
	shared := ids.New[ids.RegistryKind]()
	other := ids.New[ids.RegistryKind]()
	policies := ModelPolicies{
		shared: {Allowed: []string{"gpt-4o-mini", "gpt-5"}, Default: "gpt-4o-mini"},
		other:  {Allowed: []string{"claude-4"}, Default: "claude-4"},
	}
	tests := []struct {
		name    string
		members []LBPoolMember
		wantErr bool
	}{
		{
			name: "same registry with distinct models",
			members: []LBPoolMember{
				{RegistryID: shared, Model: "gpt-4o-mini"},
				{RegistryID: shared, Model: "gpt-5"},
			},
		},
		{
			name: "distinct registries without models stay valid",
			members: []LBPoolMember{
				{RegistryID: shared},
				{RegistryID: other},
			},
		},
		{
			name: "same registry twice without models",
			members: []LBPoolMember{
				{RegistryID: shared},
				{RegistryID: shared},
			},
			wantErr: true,
		},
		{
			name: "same registry, one member missing its model",
			members: []LBPoolMember{
				{RegistryID: shared, Model: "gpt-5"},
				{RegistryID: shared},
			},
			wantErr: true,
		},
		{
			name: "duplicate route",
			members: []LBPoolMember{
				{RegistryID: shared, Model: "gpt-5"},
				{RegistryID: shared, Model: "gpt-5"},
			},
			wantErr: true,
		},
		{
			name:    "model outside the policy allow-list",
			members: []LBPoolMember{{RegistryID: shared, Model: "gpt-4.1"}},
			wantErr: true,
		},
		{
			name:    "model outside the member allow-list",
			members: []LBPoolMember{{RegistryID: shared, Models: []string{"gpt-5"}, Model: "gpt-4o-mini"}},
			wantErr: true,
		},
		{
			name:    "blank model",
			members: []LBPoolMember{{RegistryID: shared, Model: "   "}},
			wantErr: true,
		},
		{
			name:    "weight above the cap",
			members: []LBPoolMember{{RegistryID: shared, Weight: ptrInt(MaxRegistryWeight + 1)}},
			wantErr: true,
		},
		{
			name:    "weight below the floor",
			members: []LBPoolMember{{RegistryID: shared, Weight: ptrInt(0)}},
			wantErr: true,
		},
		{
			name:    "weight inside the range",
			members: []LBPoolMember{{RegistryID: shared, Weight: ptrInt(7)}},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &LBConfig{Enabled: true, Members: tc.members}
			err := cfg.Validate(policies)
			if tc.wantErr && !errors.Is(err, ErrInvalidLBConfig) {
				t.Fatalf("err = %v, want ErrInvalidLBConfig", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestLBConfig_ValidateSmartRoutingTiers(t *testing.T) {
	t.Parallel()
	shared := ids.New[ids.RegistryKind]()
	single := ids.New[ids.RegistryKind]()
	policies := ModelPolicies{
		shared: {Allowed: []string{"gpt-4o-mini", "gpt-5"}, Default: "gpt-4o-mini"},
		single: {Allowed: []string{"claude-4"}, Default: "claude-4"},
	}
	sharedMembers := []LBPoolMember{
		{RegistryID: shared, Model: "gpt-4o-mini"},
		{RegistryID: shared, Model: "gpt-5"},
	}
	tests := []struct {
		name    string
		members []LBPoolMember
		tiers   []registry.SmartRoutingTier
		wantErr bool
	}{
		{
			name:    "tiers target distinct routes of one registry",
			members: sharedMembers,
			tiers: []registry.SmartRoutingTier{
				{MinScore: 0, RegistryID: shared, Model: "gpt-4o-mini"},
				{MinScore: 0.5, RegistryID: shared, Model: "gpt-5"},
			},
		},
		{
			name:    "tier may omit the model for a single-route registry",
			members: []LBPoolMember{{RegistryID: single}},
			tiers:   []registry.SmartRoutingTier{{MinScore: 0, RegistryID: single}},
		},
		{
			name:    "tier omits the model on a multi-route registry",
			members: sharedMembers,
			tiers:   []registry.SmartRoutingTier{{MinScore: 0, RegistryID: shared}},
			wantErr: true,
		},
		{
			name:    "tier targets a model that is not a route",
			members: sharedMembers,
			tiers:   []registry.SmartRoutingTier{{MinScore: 0, RegistryID: shared, Model: "gpt-4.1"}},
			wantErr: true,
		},
		{
			name:    "tier targets a registry outside the pool",
			members: sharedMembers,
			tiers:   []registry.SmartRoutingTier{{MinScore: 0, RegistryID: single, Model: "claude-4"}},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &LBConfig{
				Enabled:      true,
				Algorithm:    algorithm.SmartRouting,
				Members:      tc.members,
				SmartRouting: &registry.SmartRoutingConfig{Tiers: tc.tiers},
			}
			err := cfg.Validate(policies)
			if tc.wantErr && !errors.Is(err, ErrInvalidLBConfig) {
				t.Fatalf("err = %v, want ErrInvalidLBConfig", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestLBPoolMember_RouteWeight(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		member LBPoolMember
		want   int
	}{
		{name: "unset falls back", member: LBPoolMember{}, want: 3},
		{name: "zero falls back", member: LBPoolMember{Weight: ptrInt(0)}, want: 3},
		{name: "declared wins", member: LBPoolMember{Weight: ptrInt(9)}, want: 9},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.member.RouteWeight(3); got != tc.want {
				t.Fatalf("RouteWeight() = %d, want %d", got, tc.want)
			}
		})
	}
}

func ptrInt(v int) *int { return &v }
