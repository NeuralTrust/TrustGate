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
	"encoding/json"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

// A revision advertised by server/discover but refused by initialize downgrades
// the client silently: it keeps applying the newer revision's rules to responses
// the gateway builds under an older one, and rejects them as malformed.
func TestAdvertisedProtocolVersionsAreAllNegotiable(t *testing.T) {
	t.Parallel()
	// Pinned rather than derived: adding a revision here has to be a deliberate
	// edit, because advertising one obliges every response the gateway emits —
	// including the tools/call results it relays verbatim from upstreams — to
	// satisfy that revision's envelope. 2026-07-28 is on the list because
	// stampResultEnvelope meets that obligation for both kinds of result; the
	// tests below hold it to it. 2025-11-25 is on it because current clients
	// offer it in initialize, and one left off it was answered with a revision
	// it could not speak.
	require.Equal(t, []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}, advertisedProtocolVersions)
	require.Equal(t, latestProtocolVersion, advertisedProtocolVersions[0],
		"server/discover lists the preferred revision first")
	require.True(t, supportedProtocolVersions[handshakeProtocolVersion],
		"initialize falls back to the newest revision that has it, which must be negotiable")
	for _, version := range advertisedProtocolVersions {
		require.Truef(t, supportedProtocolVersions[version],
			"server/discover advertises %q but initialize cannot negotiate it", version)
	}
	require.Len(t, supportedProtocolVersions, len(advertisedProtocolVersions),
		"initialize must not negotiate a revision server/discover does not advertise")
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
			result := serverDiscoveryResult(rc, appmcp.SurfaceFingerprint(rc, nil))
			require.Equal(t, advertisedProtocolVersions, result["supportedVersions"])
			require.Equal(t, "complete", result["resultType"])
			require.Equal(t, "private", result["cacheScope"])
			require.Zero(t, result["ttlMs"])
			capabilities := result["capabilities"].(map[string]any)
			require.Len(t, capabilities, len(tc.want))
			for _, kind := range tc.want {
				require.Contains(t, capabilities, kind)
				if kind == "tools" {
					// The one surface the gateway watches and announces, so the
					// one capability it claims to notify on.
					require.Equal(t, map[string]any{"listChanged": true}, capabilities[kind])
					continue
				}
				require.Empty(t, capabilities[kind],
					"claiming a notification the gateway never sends leaves a client waiting for it")
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
	oneRC := &appconsumer.RoutableConsumer{
		Consumer:   consumer,
		Registries: []*registrydomain.Registry{notion},
	}
	twoRC := &appconsumer.RoutableConsumer{
		Consumer:   consumer,
		Registries: []*registrydomain.Registry{notion, registry("linear")},
	}
	one := serverDiscoveryResult(oneRC, appmcp.SurfaceFingerprint(oneRC, nil))
	two := serverDiscoveryResult(twoRC, appmcp.SurfaceFingerprint(twoRC, nil))

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

	pending := serverDiscoveryResult(rc, appmcp.SurfaceFingerprint(rc, nil))
	linked := serverDiscoveryResult(rc, appmcp.SurfaceFingerprint(rc,
		[]string{"cx:linear@" + linkedAt.Format(time.RFC3339Nano)}))
	reconnected := serverDiscoveryResult(rc, appmcp.SurfaceFingerprint(rc,
		[]string{"cx:linear@" + linkedAt.Add(time.Hour).Format(time.RFC3339Nano)}))

	versionOf := func(result map[string]any) string {
		return result["_meta"].(map[string]any)[modernServerInfoMetaKey].(map[string]any)["version"].(string)
	}
	require.NotEqual(t, versionOf(pending), versionOf(linked))
	require.NotEqual(t, versionOf(linked), versionOf(reconnected))
}

// The envelope the newest advertised revision requires, on both kinds of result
// the gateway produces: the ones it composes and the ones it relays from an
// upstream that has never heard of that revision.
func TestStampResultEnvelope(t *testing.T) {
	t.Parallel()

	t.Run("a relayed result is given the type it lacks", func(t *testing.T) {
		t.Parallel()
		relayed := json.RawMessage(`{"content":[{"type":"text","text":"hi"}]}`)
		out := stampResultEnvelope("tools/call", relayed).(json.RawMessage)

		var got map[string]any
		require.NoError(t, json.Unmarshal(out, &got))
		require.Equal(t, "complete", got["resultType"])
		require.NotContains(t, got, "ttlMs", "a tool call is an effect, not something to cache")
		// Everything the upstream sent is carried across untouched.
		content := got["content"].([]any)[0].(map[string]any)
		require.Equal(t, "hi", content["text"])
	})

	t.Run("an upstream that says what kind of result it is keeps it", func(t *testing.T) {
		t.Parallel()
		relayed := json.RawMessage(`{"resultType":"input_required","requestState":"s1"}`)
		out := stampResultEnvelope("tools/call", relayed).(json.RawMessage)

		var got map[string]any
		require.NoError(t, json.Unmarshal(out, &got))
		require.Equal(t, "input_required", got["resultType"],
			"overwriting this would end an upstream's interactive call on its first turn")
	})

	t.Run("a cacheable result says whose copy it is and for how long", func(t *testing.T) {
		t.Parallel()
		out := stampResultEnvelope("tools/list", map[string]any{"tools": []any{}}).(map[string]any)

		require.Equal(t, "complete", out["resultType"])
		require.Equal(t, "private", out["cacheScope"],
			"the surface is built from one principal's installs, accounts and policy")
		require.Equal(t, 0, out["ttlMs"],
			"it changes the moment they install a server or sign an account in")
	})

	t.Run("an upstream cache hint does not survive the gateway", func(t *testing.T) {
		t.Parallel()
		relayed := json.RawMessage(`{"contents":[],"cacheScope":"public","ttlMs":600000}`)
		out := stampResultEnvelope("resources/read", relayed).(json.RawMessage)

		var got map[string]any
		require.NoError(t, json.Unmarshal(out, &got))
		require.Equal(t, "private", got["cacheScope"],
			"the upstream described its own answer; this one is served per principal")
		require.Equal(t, float64(0), got["ttlMs"])
	})

	t.Run("a result that is not an object is relayed as it was", func(t *testing.T) {
		t.Parallel()
		relayed := json.RawMessage(`[1,2,3]`)
		require.Equal(t, relayed, stampResultEnvelope("tools/call", relayed))
	})

	t.Run("an empty result still says it is complete", func(t *testing.T) {
		t.Parallel()
		out := stampResultEnvelope("ping", struct{}{}).(json.RawMessage)
		require.JSONEq(t, `{"resultType":"complete"}`, string(out))
	})
}
