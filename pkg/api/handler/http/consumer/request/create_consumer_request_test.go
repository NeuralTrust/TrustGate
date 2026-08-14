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

package request

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func intPtr(v int) *int { return &v }

func TestCreateConsumerRequest_ToRegistryBindings_Weights(t *testing.T) {
	t.Parallel()
	id1 := ids.New[ids.RegistryKind]()
	id2 := ids.New[ids.RegistryKind]()
	req := CreateConsumerRequest{
		Name: "c",
		Registries: []RegistryBindingRequest{
			{ID: id1.String(), Weight: intPtr(5)},
			{ID: id2.String()},
		},
	}

	registryIDs, weights, _, err := req.ToRegistryBindings()
	if err != nil {
		t.Fatalf("ToRegistryBindings error: %v", err)
	}
	if len(registryIDs) != 2 {
		t.Fatalf("registryIDs len = %d, want 2", len(registryIDs))
	}
	if weights[id1] != 5 {
		t.Fatalf("weights[id1] = %d, want 5", weights[id1])
	}
	if weights[id2] != 1 {
		t.Fatalf("weights[id2] = %d, want default 1", weights[id2])
	}
}

func TestCreateConsumerRequest_ToRegistryBindings_RejectsNonPositiveWeight(t *testing.T) {
	t.Parallel()
	req := CreateConsumerRequest{
		Name: "c",
		Registries: []RegistryBindingRequest{
			{ID: ids.New[ids.RegistryKind]().String(), Weight: intPtr(0)},
		},
	}

	_, _, _, err := req.ToRegistryBindings()
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
}

func TestLBConfigRequest_ToDomain_RoutesPerModel(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	req := LBConfigRequest{
		Enabled:   true,
		Algorithm: "smart-routing",
		Members: []LBPoolMemberRequest{
			{RegistryID: registryID.String(), Model: "gpt-5-mini", Weight: intPtr(3)},
			{RegistryID: registryID.String(), Model: "gpt-5"},
		},
		SmartRouting: &SmartRoutingConfigRequest{
			Tiers: []SmartRoutingTierRequest{
				{MinScore: 0, RegistryID: registryID.String(), Model: "gpt-5-mini"},
				{MinScore: 0.5, RegistryID: registryID.String(), Model: "gpt-5"},
			},
		},
	}

	cfg, err := req.ToDomain()
	if err != nil {
		t.Fatalf("ToDomain error: %v", err)
	}
	if len(cfg.Members) != 2 {
		t.Fatalf("members len = %d, want 2", len(cfg.Members))
	}
	if got := cfg.Members[0].RouteModel(); got != "gpt-5-mini" {
		t.Fatalf("members[0].Model = %q, want gpt-5-mini", got)
	}
	if got := cfg.Members[0].RouteWeight(1); got != 3 {
		t.Fatalf("members[0] weight = %d, want 3", got)
	}
	if got := cfg.Members[1].RouteWeight(7); got != 7 {
		t.Fatalf("members[1] weight = %d, want the fallback 7", got)
	}
	if got := cfg.SmartRouting.Tiers[1].RouteModel(); got != "gpt-5" {
		t.Fatalf("tiers[1].Model = %q, want gpt-5", got)
	}
}

func TestCreateConsumerRequest_ToRegistryBindings_RejectsWeightAboveMax(t *testing.T) {
	t.Parallel()
	req := CreateConsumerRequest{
		Name: "c",
		Registries: []RegistryBindingRequest{
			{ID: ids.New[ids.RegistryKind]().String(), Weight: intPtr(domain.MaxRegistryWeight + 1)},
		},
	}

	_, _, _, err := req.ToRegistryBindings()
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
}

func TestCreateConsumerRequest_ToMCPPolicy_ProtocolAcceptance(t *testing.T) {
	t.Parallel()

	t.Run("empty omitted", func(t *testing.T) {
		t.Parallel()
		got, err := CreateConsumerRequest{Name: "c"}.ToMCPPolicy()
		if err != nil {
			t.Fatalf("ToMCPPolicy error: %v", err)
		}
		if got != nil {
			t.Fatalf("ToMCPPolicy = %+v, want nil", got)
		}
	})

	t.Run("legacy_only", func(t *testing.T) {
		t.Parallel()
		got, err := CreateConsumerRequest{Name: "c", ProtocolAcceptance: "LEGACY_ONLY"}.ToMCPPolicy()
		if err != nil {
			t.Fatalf("ToMCPPolicy error: %v", err)
		}
		if got == nil || got.ProtocolAcceptance != domain.ProtocolAcceptanceLegacyOnly {
			t.Fatalf("ProtocolAcceptance = %v, want legacy_only", got)
		}
	})

	t.Run("dual_era", func(t *testing.T) {
		t.Parallel()
		got, err := CreateConsumerRequest{Name: "c", ProtocolAcceptance: "dual_era"}.ToMCPPolicy()
		if err != nil {
			t.Fatalf("ToMCPPolicy error: %v", err)
		}
		if got == nil || got.ProtocolAcceptance != domain.ProtocolAcceptanceDualEra {
			t.Fatalf("ProtocolAcceptance = %v, want dual_era", got)
		}
	})
}
