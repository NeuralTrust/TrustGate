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
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

// A revision advertised by the legacy-era server/discover but refused by
// initialize downgrades the client silently: it keeps applying the newer
// revision's rules to responses the gateway builds under an older one, and
// rejects them as malformed.
func TestAdvertisedProtocolVersionsAreAllNegotiable(t *testing.T) {
	t.Parallel()
	// Pinned rather than derived: adding a revision here has to be a deliberate
	// edit, because advertising one obliges every response the gateway emits —
	// including the tools/call results it relays verbatim from upstreams — to
	// satisfy that revision's envelope. The modern revision is deliberately
	// absent: it is negotiated through the modern era's own boundary.
	require.Equal(t, []string{"2025-06-18", "2025-03-26", "2024-11-05"}, advertisedProtocolVersions)
	require.Equal(t, latestLegacyProtocolVersion, advertisedProtocolVersions[0],
		"the preferred revision must be the one initialize falls back to")
	for _, version := range advertisedProtocolVersions {
		require.Truef(t, isSupportedProtocolVersion(version),
			"server/discover advertises %q but initialize cannot negotiate it", version)
		require.Truef(t, isLegacyProtocolVersion(version),
			"the legacy-era advertisement must not name a modern revision: %q", version)
	}
}

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
			require.Equal(t,
				supportedProtocolVersions,
				serverDiscoveryResultWith(rc, false, false, false)["supportedVersions"],
				"the modern era advertises every supported revision")
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
	normalized, err := normalizeModernResult("server/discover", serverDiscoveryResultWith(rc, false, false, false), rc, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "complete", normalized["resultType"])
	require.Equal(t, modernCacheTTLDefault, normalized["ttlMs"])
	require.Equal(t, "private", normalized["cacheScope"])
	serverInfo := normalized["_meta"].(map[string]any)[modernServerInfoKey].(map[string]any)
	require.Equal(t, serverName, serverInfo["name"])
	require.Equal(t, serverVersion+"+"+appmcp.SurfaceFingerprint(rc, nil), serverInfo["version"])
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

	nilFingerprint := appmcp.SurfaceFingerprint(nilToolkit, nil)
	emptyFingerprint := appmcp.SurfaceFingerprint(emptyToolkit, nil)
	require.NotEqual(t, nilFingerprint, emptyFingerprint)

	nilResult, err := normalizeModernResult("server/discover", serverDiscoveryResultWith(nilToolkit, false, false, false), nilToolkit, nil, nil)
	require.NoError(t, err)
	emptyResult, err := normalizeModernResult(
		"server/discover",
		serverDiscoveryResultWith(emptyToolkit, false, false, false),
		emptyToolkit,
		nil,
		nil,
	)
	require.NoError(t, err)
	nilVersion := nilResult["_meta"].(map[string]any)[modernServerInfoKey].(map[string]any)["version"]
	emptyVersion := emptyResult["_meta"].(map[string]any)[modernServerInfoKey].(map[string]any)["version"]
	require.NotEqual(t, nilVersion, emptyVersion)
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
