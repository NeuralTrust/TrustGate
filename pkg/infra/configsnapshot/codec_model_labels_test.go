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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodecRoundTripsRegistryModelLabels(t *testing.T) {
	t.Parallel()
	const arn = "arn:aws:bedrock:eu-west-1:123456789012:application-inference-profile/abc123"
	codec := configsnapshot.NewCodec()
	reg, err := registrydomain.NewLLMRegistry(ids.New[ids.GatewayKind](), "bedrock", "", &registrydomain.LLMTarget{
		Provider:    "bedrock",
		Auth:        registrydomain.NewAPIKeyAuth("sk-test"),
		ModelLabels: map[string]string{arn: "Claude Sonnet (prod)"},
	})
	require.NoError(t, err)

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{Version: "v1", Registries: []registrydomain.Registry{*reg}}))
	require.NoError(t, err)
	snap, err := codec.Decode(raw)
	require.NoError(t, err)

	require.Len(t, snap.Data().Registries, 1)
	assert.Equal(t, map[string]string{arn: "Claude Sonnet (prod)"}, snap.Data().Registries[0].ModelLabels())
}
