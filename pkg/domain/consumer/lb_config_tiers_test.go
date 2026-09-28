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

func TestConsumer_ValidateRejectsUnknownSmartRoutingTierRegistry(t *testing.T) {
	t.Parallel()
	attached := ids.New[ids.RegistryKind]()
	unknown := ids.New[ids.RegistryKind]()

	tests := []struct {
		name     string
		lbConfig *LBConfig
		wantErr  bool
	}{
		{
			name: "disabled pool with a tier on an unknown registry",
			lbConfig: &LBConfig{
				Algorithm: algorithm.SmartRouting,
				Members:   []LBPoolMember{{RegistryID: attached, Model: "gpt-4o"}},
				SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{
					{MinScore: 0, RegistryID: unknown, Model: "gpt-4.1-nano"},
				}},
			},
			wantErr: true,
		},
		{
			name: "disabled pool with a nil tier registry",
			lbConfig: &LBConfig{
				Algorithm: algorithm.SmartRouting,
				Members:   []LBPoolMember{{RegistryID: attached, Model: "gpt-4o"}},
				SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{
					{MinScore: 0, RegistryID: ids.RegistryID{}},
				}},
			},
			wantErr: true,
		},
		{
			name: "enabled pool with a tier on an unknown registry",
			lbConfig: &LBConfig{
				Enabled:   true,
				Algorithm: algorithm.SmartRouting,
				Members:   []LBPoolMember{{RegistryID: attached, Model: "gpt-4o"}},
				SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{
					{MinScore: 0, RegistryID: unknown, Model: "gpt-4.1-nano"},
				}},
			},
			wantErr: true,
		},
		{
			name: "disabled pool with a tier on an attached registry",
			lbConfig: &LBConfig{
				Algorithm: algorithm.SmartRouting,
				Members:   []LBPoolMember{{RegistryID: attached, Model: "gpt-4o"}},
				SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{
					{MinScore: 0, RegistryID: attached, Model: "gpt-4o"},
				}},
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(CreateParams{
				GatewayID:     ids.New[ids.GatewayKind](),
				Name:          "tiered",
				Type:          TypeLLM,
				RegistryIDs:   []ids.RegistryID{attached},
				ModelPolicies: ModelPolicies{attached: {Allowed: []string{"gpt-4o"}}},
				LBConfig:      tc.lbConfig,
			})
			if tc.wantErr && !errors.Is(err, ErrInvalidLBConfig) {
				t.Fatalf("err = %v, want ErrInvalidLBConfig", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
