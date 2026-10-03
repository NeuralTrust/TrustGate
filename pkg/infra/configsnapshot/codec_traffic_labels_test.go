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
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/require"
)

func TestCodecRoundTrip_CarriesTrafficLabeling(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	rate := 0.5
	gw, err := gatewaydomain.New("labeled")
	require.NoError(t, err)
	gw.TrafficLabeling = &trafficlabel.Config{
		Enabled:       true,
		RegistryID:    ids.New[ids.RegistryKind]().String(),
		Model:         "gpt-4o-mini",
		MessageWindow: 4,
		SamplingRate:  &rate,
	}
	bare, err := gatewaydomain.New("bare")
	require.NoError(t, err)

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{Gateways: []gatewaydomain.Gateway{*gw, *bare}}))
	require.NoError(t, err)
	snap, err := codec.Decode(raw)
	require.NoError(t, err)

	got, ok := snap.GatewayByID(gw.ID)
	require.True(t, ok)
	require.Equal(t, gw.TrafficLabeling, got.TrafficLabeling)

	gotBare, ok := snap.GatewayByID(bare.ID)
	require.True(t, ok)
	require.Nil(t, gotBare.TrafficLabeling)
}

func TestCodecRoundTrip_CarriesConsumerLabels(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	gw, err := gatewaydomain.New("labeled")
	require.NoError(t, err)
	labeled := consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw.ID, Name: "chat", Slug: "chat", Type: consumerdomain.TypeLLM, Active: true,
		Labels: []trafficlabel.Label{{ID: "l-1", Name: "Billing", Instructions: "refunds", Examples: []string{"refund?"}}},
	}
	bare := consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw.ID, Name: "bare", Slug: "bare", Type: consumerdomain.TypeLLM, Active: true,
	}

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{
		Gateways:  []gatewaydomain.Gateway{*gw},
		Consumers: []consumerdomain.Consumer{labeled, bare},
	}))
	require.NoError(t, err)
	snap, err := codec.Decode(raw)
	require.NoError(t, err)

	got, ok := snap.ConsumerByID(labeled.ID)
	require.True(t, ok)
	require.Equal(t, labeled.Labels, got.Labels)
	gotBare, ok := snap.ConsumerByID(bare.ID)
	require.True(t, ok)
	require.Nil(t, gotBare.Labels)
}
