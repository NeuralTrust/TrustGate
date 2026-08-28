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
	"time"

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
			result := serverDiscoveryResult(rc, nil)
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
	}, nil)
	two := serverDiscoveryResult(&appconsumer.RoutableConsumer{
		Consumer:   consumer,
		Registries: []*registrydomain.Registry{notion, registry("linear")},
	}, nil)

	require.Zero(t, one["ttlMs"])
	require.Zero(t, two["ttlMs"])
	oneInfo := one["_meta"].(map[string]any)[modernServerInfoMetaKey].(map[string]any)
	twoInfo := two["_meta"].(map[string]any)[modernServerInfoMetaKey].(map[string]any)
	require.NotEqual(t, oneInfo["version"], twoInfo["version"])
}

// Connecting an account on the connect page changes which upstreams federate
// without touching any registry, so the reported version has to move with it or
// a version-keyed client keeps replaying its cached tool list.
func TestServerDiscoveryResultChangesAfterConnectingAnAccount(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	linear, err := registrydomain.NewMCPRegistry(
		gatewayID,
		"linear",
		"",
		&registrydomain.MCPTarget{
			URL: "https://linear.example.com/mcp",
			Auth: &registrydomain.MCPAuth{
				Mode:         registrydomain.MCPAuthModeForwarded,
				Provider:     "linear",
				ClientID:     "cid",
				AuthorizeURL: "https://linear.example.com/authorize",
				TokenURL:     "https://linear.example.com/token",
			},
		},
	)
	require.NoError(t, err)
	rc := &appconsumer.RoutableConsumer{
		Consumer:   &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID},
		Registries: []*registrydomain.Registry{linear},
	}
	linkedAt := time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC)

	pending := serverDiscoveryResult(rc, nil)
	linked := serverDiscoveryResult(rc, []string{"cx:linear@" + linkedAt.Format(time.RFC3339Nano)})
	reconnected := serverDiscoveryResult(rc, []string{"cx:linear@" + linkedAt.Add(time.Hour).Format(time.RFC3339Nano)})

	versionOf := func(result map[string]any) string {
		return result["_meta"].(map[string]any)[modernServerInfoMetaKey].(map[string]any)["version"].(string)
	}
	require.NotEqual(t, versionOf(pending), versionOf(linked))
	require.NotEqual(t, versionOf(linked), versionOf(reconnected))
}
