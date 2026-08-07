package mcp

import (
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
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
			result := serverDiscoveryResult(rc)
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

func TestServerDiscoveryResultUsesModernNormalization(t *testing.T) {
	t.Parallel()
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](),
		},
	}
	normalized, err := normalizeModernResult("server/discover", serverDiscoveryResult(rc), rc)
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

	nilResult, err := normalizeModernResult("server/discover", serverDiscoveryResult(nilToolkit), nilToolkit)
	require.NoError(t, err)
	emptyResult, err := normalizeModernResult("server/discover", serverDiscoveryResult(emptyToolkit), emptyToolkit)
	require.NoError(t, err)
	nilVersion := nilResult["_meta"].(map[string]any)[modernServerInfoKey].(map[string]any)["version"]
	emptyVersion := emptyResult["_meta"].(map[string]any)[modernServerInfoKey].(map[string]any)["version"]
	require.NotEqual(t, nilVersion, emptyVersion)
}
