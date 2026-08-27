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

package mcp

import (
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

func TestServerDiscoveryResultCapabilities(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	cases := []struct {
		name   string
		policy *consumerdomain.MCPPolicy
		want   []string
	}{
		{
			name: "nil toolkit",
			want: []string{"tools", "prompts", "resources"},
		},
		{
			name:   "explicit empty toolkit",
			policy: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{}},
		},
		{
			name: "tools only",
			policy: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
				{RegistryID: registryID, Tool: "search"},
			}},
			want: []string{"tools"},
		},
		{
			name: "represented kinds only",
			policy: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
				{RegistryID: registryID, Prompt: "summarize"},
				{RegistryID: registryID, Resource: "file:///*"},
			}},
			want: []string{"prompts", "resources"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rc := &appconsumer.RoutableConsumer{
				Consumer: &consumerdomain.Consumer{MCP: tc.policy},
			}
			result := serverDiscoveryResult(rc)
			require.Equal(t, advertisedProtocolVersions, result["supportedVersions"])
			require.Equal(t, "complete", result["resultType"])
			require.Equal(t, "private", result["cacheScope"])
			require.Zero(t, result["ttlMs"])
			capabilities := result["capabilities"].(map[string]any)
			require.Len(t, capabilities, len(tc.want))
			for _, kind := range tc.want {
				require.Contains(t, capabilities, kind)
				require.Empty(t, capabilities[kind])
			}
			serverInfo := result["_meta"].(map[string]any)[modernServerInfoMetaKey].(map[string]any)
			require.Equal(t, serverName, serverInfo["name"])
			require.Contains(t, serverInfo["version"], serverVersion+"+")
		})
	}
}

func TestServerDiscoveryResultChangesAfterRegistryAttachment(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	registry := func(name string) *registrydomain.Registry {
		result, err := registrydomain.NewMCPRegistry(
			gatewayID,
			name,
			"",
			&registrydomain.MCPTarget{URL: "https://" + name + ".example.com/mcp"},
		)
		require.NoError(t, err)
		return result
	}
	consumer := &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind]()}
	notion := registry("notion")
	one := serverDiscoveryResult(&appconsumer.RoutableConsumer{
		Consumer:   consumer,
		Registries: []*registrydomain.Registry{notion},
	})
	two := serverDiscoveryResult(&appconsumer.RoutableConsumer{
		Consumer:   consumer,
		Registries: []*registrydomain.Registry{notion, registry("linear")},
	})

	require.Zero(t, one["ttlMs"])
	require.Zero(t, two["ttlMs"])
	oneInfo := one["_meta"].(map[string]any)[modernServerInfoMetaKey].(map[string]any)
	twoInfo := two["_meta"].(map[string]any)[modernServerInfoMetaKey].(map[string]any)
	require.NotEqual(t, oneInfo["version"], twoInfo["version"])
}
