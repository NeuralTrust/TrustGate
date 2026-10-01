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

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/require"
)

func TestCodecRoundTrip_CarriesTopicClassification(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	threshold := 0.65
	gw, err := gatewaydomain.New("classified")
	require.NoError(t, err)
	gw.TopicClassification = &topic.Config{
		Enabled:       true,
		Topics:        []topic.Topic{{Name: "billing", Definition: "refunds and invoices"}},
		Threshold:     &threshold,
		MessageWindow: 4,
	}
	bare, err := gatewaydomain.New("bare")
	require.NoError(t, err)

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{Gateways: []gatewaydomain.Gateway{*gw, *bare}}))
	require.NoError(t, err)
	snap, err := codec.Decode(raw)
	require.NoError(t, err)

	got, ok := snap.GatewayByID(gw.ID)
	require.True(t, ok)
	require.Equal(t, gw.TopicClassification, got.TopicClassification)

	gotBare, ok := snap.GatewayByID(bare.ID)
	require.True(t, ok)
	require.Nil(t, gotBare.TopicClassification)
}
