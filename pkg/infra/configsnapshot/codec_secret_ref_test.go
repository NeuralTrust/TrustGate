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
	"bytes"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A reference is configuration, not a value: the snapshot carries it
// verbatim and in the clear, which is also what lets the config-sync server
// find it in the bytes it serves and withhold them from planes that predate
// references.
func TestCodecCarriesSecretReferencesVerbatim(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()
	const apiKeyRef = "secret://vault/llm/openai?version=3#api_key"
	const headerRef = "secret://aws/mcp/asana"

	gwID := ids.New[ids.GatewayKind]()
	llm := registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gwID, Name: "openai", Type: registrydomain.TypeLLM, Enabled: true,
		LLMTarget: &registrydomain.LLMTarget{Provider: "openai", Auth: registrydomain.NewAPIKeyAuth(apiKeyRef)},
		CreatedAt: time.Unix(0, 0).UTC(),
	}
	mcp := registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gwID, Name: "asana", Type: registrydomain.TypeMCP, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{
			URL:  "https://mcp.example.com",
			Auth: &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: headerRef},
		},
		CreatedAt: time.Unix(0, 0).UTC(),
	}

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{Registries: []registrydomain.Registry{llm, mcp}}))
	require.NoError(t, err)
	assert.True(t, bytes.Contains(raw, []byte(apiKeyRef)), "the API key reference must be in the served bytes verbatim")
	assert.True(t, bytes.Contains(raw, []byte(headerRef)), "the header reference must be in the served bytes verbatim")

	snap, err := codec.Decode(raw)
	require.NoError(t, err)
	gotLLM, ok := snap.RegistryByID(llm.ID)
	require.True(t, ok)
	assert.Equal(t, apiKeyRef, gotLLM.LLMTarget.Auth.APIKey.APIKey)
	gotMCP, ok := snap.RegistryByID(mcp.ID)
	require.True(t, ok)
	assert.Equal(t, headerRef, gotMCP.MCPTarget.Auth.Value)
	assert.False(t, gotLLM.CredentialUnavailable(), "decoding never resolves or marks a reference")
}
