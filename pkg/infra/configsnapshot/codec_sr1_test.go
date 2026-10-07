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

package configsnapshot_test

import (
	"context"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/adapters"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodecRejectsInvalidSmartRoutingAndPreservesRepositoryReads(t *testing.T) {
	for _, kind := range []string{"one rung", "four rungs", "ambiguous pin", "invalid explicit cuts"} {
		t.Run(kind, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			registryID := ids.New[ids.RegistryKind]()
			valid := consumerdomain.Consumer{
				ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID, Slug: "valid", Active: true,
				RegistryIDs:   []ids.RegistryID{registryID},
				ModelPolicies: consumerdomain.ModelPolicies{registryID: {Allowed: []string{"low", "mid", "high"}}},
				LBConfig: &consumerdomain.LBConfig{Enabled: true, Algorithm: algorithm.SmartRouting,
					Members: []consumerdomain.LBPoolMember{
						{RegistryID: registryID, Model: "low"},
						{RegistryID: registryID, Model: "mid"},
						{RegistryID: registryID, Model: "high"},
					},
					SmartRouting: &registrydomain.SmartRoutingConfig{SR1: &registrydomain.SR1Config{CacheTTLSeconds: 300}, Tiers: []registrydomain.SmartRoutingTier{
						{RegistryID: registryID, Model: "high", MinScore: .45},
						{RegistryID: registryID, Model: "low", MinScore: 0},
						{RegistryID: registryID, Model: "mid", MinScore: .187},
					}},
				},
			}
			invalid := consumerdomain.Consumer{
				ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID, Slug: "invalid", Active: true,
				LBConfig: &consumerdomain.LBConfig{Enabled: true, Algorithm: algorithm.SmartRouting,
					SmartRouting: &registrydomain.SmartRoutingConfig{},
				},
			}
			count := 2
			switch kind {
			case "one rung":
				count = 1
			case "four rungs":
				count = 4
			}
			for i := 0; i < count; i++ {
				model := []string{"first", "second", "third", "fourth"}[i]
				member := consumerdomain.LBPoolMember{RegistryID: ids.New[ids.RegistryKind](), Model: model}
				tier := registrydomain.SmartRoutingTier{RegistryID: member.RegistryID, Model: model, MinScore: float64(i) / 4}
				if kind == "ambiguous pin" && i == 0 {
					member.Model, tier.Model = "", ""
					member.Models = []string{"first", "other"}
				}
				invalid.LBConfig.Members = append(invalid.LBConfig.Members, member)
				invalid.LBConfig.SmartRouting.Tiers = append(invalid.LBConfig.SmartRouting.Tiers, tier)
			}
			if kind == "invalid explicit cuts" {
				invalid.LBConfig.SmartRouting.SR1 = &registrydomain.SR1Config{CacheTTLSeconds: 300, EscapeHatchEnabled: false}
			}
			err := invalid.LBConfig.Validate(nil)
			require.Error(t, err, "the fixture must require operator repair")
			codec := configsnapshot.NewCodec()
			data := readmodel.Data{
				Gateways:   []gatewaydomain.Gateway{{ID: gatewayID, Slug: "gateway", Entitlements: gatewaydomain.DefaultEntitlements()}},
				Consumers:  []consumerdomain.Consumer{valid, invalid},
				Registries: []registrydomain.Registry{{ID: registryID, GatewayID: gatewayID}},
			}
			_, err = codec.Encode(readmodel.Build(data))
			require.Error(t, err, "invalid historical routing must be repaired before snapshot publication")
			validData := data
			validData.Consumers = []consumerdomain.Consumer{valid}
			raw, err := codec.Encode(readmodel.Build(validData))
			require.NoError(t, err)
			snapshot, err := codec.Decode(raw)
			require.NoError(t, err)
			require.Len(t, snapshot.Data().Consumers, 1)
			gotValid, ok := snapshot.ConsumerByID(valid.ID)
			require.True(t, ok)
			require.NotNil(t, gotValid.LBConfig.SmartRouting.SR1)
			assert.False(t, gotValid.LBConfig.SmartRouting.SR1.EscapeEnabled())
			assert.Equal(t, 300, gotValid.LBConfig.SmartRouting.SR1.CacheTTLSeconds)
			assert.Equal(t, valid.LBConfig.SmartRouting, gotValid.LBConfig.SmartRouting, "serialization must preserve tier order and cuts")
			reraw, err := codec.Encode(snapshot)
			require.NoError(t, err)
			assert.Equal(t, raw, reraw, "canonical consumers must converge without normalization")

			store := configsync.NewMemoryStore[*readmodel.Snapshot]()
			// Repository cloning still preserves stored historical data for repair;
			// this bypasses snapshot admission explicitly, without inventing a ladder.
			store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: "historical", Snapshot: readmodel.Build(data)})
			repository := adapters.NewConsumerRepository(store)
			items, err := repository.ListByGateway(context.Background(), gatewayID)
			require.NoError(t, err, "cloneJSON must not let invalid routing block unrelated reads")
			require.Len(t, items, 2)
			clone, err := repository.FindByID(context.Background(), invalid.ID)
			require.NoError(t, err)
			assert.Equal(t, invalid.LBConfig.SmartRouting, clone.LBConfig.SmartRouting)
			clone.LBConfig.SmartRouting.Tiers[0].Model = "changed"
			fresh, err := repository.FindByID(context.Background(), invalid.ID)
			require.NoError(t, err)
			assert.Equal(t, invalid.LBConfig.SmartRouting.Tiers[0].Model, fresh.LBConfig.SmartRouting.Tiers[0].Model)
		})
	}
}
