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
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rc := &appconsumer.RoutableConsumer{
				Consumer: &consumerdomain.Consumer{MCP: tc.policy},
			}
			result := serverDiscoveryResult(rc, false)
			require.Equal(t, supportedProtocolVersions, result["supportedVersions"])
			capabilities := result["capabilities"].(map[string]any)
			require.Len(t, capabilities, len(tc.want))
			for _, kind := range tc.want {
				require.Contains(t, capabilities, kind)
				require.Empty(t, capabilities[kind])
			}
		})
	}
}

// listChanged merges into the kinds already advertised and survives the tasks
// extension, which is the whole reason it runs as a post-pass: addCapability
// replaces the per-kind map on every call.
func TestServerDiscoveryResultAdvertisesListChanged(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	cases := []struct {
		name        string
		policy      *consumerdomain.MCPPolicy
		mrtr        bool
		tasks       bool
		apps        bool
		listChanged bool
		want        map[string]any
	}{
		{
			name: "off leaves the advertisement untouched",
			want: map[string]any{
				"tools":     map[string]any{},
				"prompts":   map[string]any{},
				"resources": map[string]any{},
			},
		},
		{
			name:        "on marks every visible kind",
			listChanged: true,
			want: map[string]any{
				"tools":     map[string]any{"listChanged": true},
				"prompts":   map[string]any{"listChanged": true},
				"resources": map[string]any{"listChanged": true},
			},
		},
		{
			name:        "on keeps the input-requests capability it merges into",
			mrtr:        true,
			listChanged: true,
			want: map[string]any{
				"tools":     map[string]any{"inputRequests": map[string]any{}, "listChanged": true},
				"prompts":   map[string]any{"listChanged": true},
				"resources": map[string]any{"listChanged": true},
			},
		},
		{
			name:        "on survives the tasks extension",
			tasks:       true,
			apps:        true,
			listChanged: true,
			want: map[string]any{
				"tools":     map[string]any{"listChanged": true},
				"prompts":   map[string]any{"listChanged": true},
				"resources": map[string]any{"listChanged": true},
				"extensions": map[string]any{
					"io.modelcontextprotocol/tasks": map[string]any{},
					"io.modelcontextprotocol/ui": map[string]any{
						"mimeTypes": []string{"text/html;profile=mcp-app"},
					},
				},
			},
		},
		{
			name: "a kind the toolkit hides stays absent",
			policy: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
				{RegistryID: registryID, Prompt: "summarize"},
			}},
			listChanged: true,
			want: map[string]any{
				"prompts": map[string]any{"listChanged": true},
			},
		},
		{
			name:        "an empty surface advertises nothing",
			policy:      &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{}},
			listChanged: true,
			want:        map[string]any{},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rc := &appconsumer.RoutableConsumer{
				Consumer: &consumerdomain.Consumer{MCP: tc.policy},
			}
			result := serverDiscoveryResultWith(rc, tc.mrtr, tc.tasks, tc.listChanged)
			addAppsExtension(result["capabilities"].(map[string]any), tc.apps)
			require.Equal(t, tc.want, result["capabilities"])
		})
	}
}

// A lease is advertised from configuration and known registry state alone, so a
// consumer with no modern upstream is never told notifications are available.
func TestSubscriptionsEndToEndNeedsAModernUpstream(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	modern, err := registrydomain.NewMCPRegistry(gatewayID, "modern", "", &registrydomain.MCPTarget{
		URL:          "https://a.example.com/mcp",
		ProtocolMode: registrydomain.MCPProtocolModeModern,
	})
	require.NoError(t, err)
	legacy, err := registrydomain.NewMCPRegistry(gatewayID, "legacy", "", &registrydomain.MCPTarget{
		URL:          "https://b.example.com/mcp",
		ProtocolMode: registrydomain.MCPProtocolModeLegacy,
	})
	require.NoError(t, err)

	enabled := SubscriptionsSupport{
		On:       true,
		Registry: appmcp.NewSubscriptionRegistry(appmcp.SubscriptionCaps{MaxStreams: 1}),
		Policy:   mocks.NewSubscriptionPolicy(t),
	}
	cases := []struct {
		name       string
		subs       SubscriptionsSupport
		registries []*registrydomain.Registry
		want       bool
	}{
		{name: "off", subs: SubscriptionsSupport{}, registries: []*registrydomain.Registry{modern}},
		{name: "on with a modern upstream", subs: enabled, registries: []*registrydomain.Registry{modern}, want: true},
		{name: "on with a legacy upstream only", subs: enabled, registries: []*registrydomain.Registry{legacy}},
		{name: "on with no upstream", subs: enabled},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rc := &appconsumer.RoutableConsumer{
				Consumer:   &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind]()},
				Registries: tc.registries,
			}
			require.Equal(t, tc.want, subscriptionsEndToEnd(tc.subs, rc))
		})
	}
}

func TestServerDiscoveryResultUsesModernNormalization(t *testing.T) {
	t.Parallel()
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](),
		},
	}
	normalized, err := normalizeModernResult("server/discover", serverDiscoveryResult(rc, false), rc, nil)
	require.NoError(t, err)
	require.Equal(t, "complete", normalized["resultType"])
	require.Equal(t, modernCacheTTLDefault, normalized["ttlMs"])
	require.Equal(t, "private", normalized["cacheScope"])
	serverInfo := normalized["_meta"].(map[string]any)[modernServerInfoKey].(map[string]any)
	require.Equal(t, serverName, serverInfo["name"])
	require.Equal(t, serverVersion+"+"+surfaceFingerprint(rc), serverInfo["version"])
}

func TestSurfaceFingerprintDistinguishesNilAndEmptyToolkit(t *testing.T) {
	t.Parallel()
	consumerID := ids.New[ids.ConsumerKind]()
	nilToolkit := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{ID: consumerID},
	}
	emptyToolkit := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:  consumerID,
			MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{}},
		},
	}

	nilFingerprint := surfaceFingerprint(nilToolkit)
	emptyFingerprint := surfaceFingerprint(emptyToolkit)
	require.NotEqual(t, nilFingerprint, emptyFingerprint)

	nilResult, err := normalizeModernResult("server/discover", serverDiscoveryResult(nilToolkit, false), nilToolkit, nil)
	require.NoError(t, err)
	emptyResult, err := normalizeModernResult(
		"server/discover",
		serverDiscoveryResult(emptyToolkit, false),
		emptyToolkit,
		nil,
	)
	require.NoError(t, err)
	nilVersion := nilResult["_meta"].(map[string]any)[modernServerInfoKey].(map[string]any)["version"]
	emptyVersion := emptyResult["_meta"].(map[string]any)[modernServerInfoKey].(map[string]any)["version"]
	require.NotEqual(t, nilVersion, emptyVersion)
}
