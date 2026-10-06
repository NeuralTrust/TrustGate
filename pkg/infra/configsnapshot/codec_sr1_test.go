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

func TestCodecSR1MigrationDoesNotLetInvalidConsumerBlockSnapshot(t *testing.T) {
	for _, kind := range []string{"one rung", "four rungs", "ambiguous pin", "invalid explicit cuts"} {
		t.Run(kind, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			registryID := ids.New[ids.RegistryKind]()
			valid := consumerdomain.Consumer{
				ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID, Slug: "valid", Active: true,
				LBConfig: &consumerdomain.LBConfig{Enabled: true, Algorithm: algorithm.SmartRouting,
					Members: []consumerdomain.LBPoolMember{
						{RegistryID: registryID, Model: "low"},
						{RegistryID: registryID, Model: "mid"},
						{RegistryID: registryID, Model: "high"},
					},
					SmartRouting: &registrydomain.SmartRoutingConfig{Tiers: []registrydomain.SmartRoutingTier{
						{RegistryID: registryID, Model: "high", MinScore: .8},
						{RegistryID: registryID, Model: "low", MinScore: .1},
						{RegistryID: registryID, Model: "mid", MinScore: .4},
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
				off := false
				invalid.LBConfig.SmartRouting.SR1 = &registrydomain.SR1Config{CacheTTLSeconds: 300, EscapeHatchEnabled: &off}
			}
			_, err := invalid.LBConfig.NormalizeSmartRouting(nil)
			require.Error(t, err, "the fixture must require operator repair")
			codec := configsnapshot.NewCodec()
			raw, err := codec.Encode(readmodel.Build(readmodel.Data{
				Gateways:  []gatewaydomain.Gateway{{ID: gatewayID, Slug: "gateway", Entitlements: gatewaydomain.DefaultEntitlements()}},
				Consumers: []consumerdomain.Consumer{valid, invalid},
			}))
			require.NoError(t, err, "one invalid consumer must not stop config sync")
			snapshot, err := codec.Decode(raw)
			require.NoError(t, err)
			require.Len(t, snapshot.Data().Consumers, 2)
			gotValid, ok := snapshot.ConsumerByID(valid.ID)
			require.True(t, ok)
			require.NotNil(t, gotValid.LBConfig.SmartRouting.SR1)
			require.NotNil(t, gotValid.LBConfig.SmartRouting.SR1.EscapeHatchEnabled)
			assert.False(t, gotValid.LBConfig.SmartRouting.SR1.EscapeEnabled())
			assert.Equal(t, 300, gotValid.LBConfig.SmartRouting.SR1.CacheTTLSeconds)
			for i, cut := range []float64{0, .187, .45} {
				assert.Equal(t, cut, gotValid.LBConfig.SmartRouting.Tiers[i].MinScore)
				assert.Equal(t, []string{"low", "mid", "high"}[i], gotValid.LBConfig.SmartRouting.Tiers[i].Model)
			}
			gotInvalid, ok := snapshot.ConsumerByID(invalid.ID)
			require.True(t, ok)
			assert.Equal(t, invalid.LBConfig.Members, gotInvalid.LBConfig.Members)
			assert.Equal(t, invalid.LBConfig.SmartRouting, gotInvalid.LBConfig.SmartRouting)
			_, err = gotInvalid.LBConfig.NormalizeSmartRouting(nil)
			require.Error(t, err, "serialization must not invent a repaired ladder")
			reraw, err := codec.Encode(snapshot)
			require.NoError(t, err)
			assert.Equal(t, raw, reraw, "canonical valid and preserved invalid consumers must converge")

			store := configsync.NewMemoryStore[*readmodel.Snapshot]()
			store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: codec.Version(raw), Snapshot: snapshot})
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
