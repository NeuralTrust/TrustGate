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
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

func mrtrRegistry(t *testing.T, mode registrydomain.MCPProtocolMode) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(
		ids.New[ids.GatewayKind](), "github", "",
		&registrydomain.MCPTarget{URL: "https://a.example.com/mcp", ProtocolMode: mode},
	)
	require.NoError(t, err)
	return reg
}

func mrtrRoutable(registries ...*registrydomain.Registry) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{
		Consumer:   &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind]()},
		Registries: registries,
	}
}

// Mediation is only advertised when it can survive the whole path: a secret must
// be configured and at least one bound upstream must speak the modern protocol.
func TestMRTREndToEnd(t *testing.T) {
	t.Parallel()
	modern := mrtrRegistry(t, registrydomain.MCPProtocolModeModern)
	legacy := mrtrRegistry(t, registrydomain.MCPProtocolModeLegacy)
	cases := []struct {
		name   string
		signer *appmcp.TicketSigner
		rc     *appconsumer.RoutableConsumer
		want   bool
	}{
		{name: "no signer", signer: nil, rc: mrtrRoutable(modern)},
		{
			name:   "empty secret",
			signer: appmcp.NewTicketSigner("", "", 0, 0),
			rc:     mrtrRoutable(modern),
		},
		{
			name:   "legacy upstream only",
			signer: appmcp.NewTicketSigner("secret", "", 0, 0),
			rc:     mrtrRoutable(legacy),
		},
		{
			name:   "secret and modern upstream",
			signer: appmcp.NewTicketSigner("secret", "", 0, 0),
			rc:     mrtrRoutable(modern),
			want:   true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, mrtrEndToEnd(tc.signer, tc.rc))
		})
	}
}

// The continuation capability rides on tools only, and only when mediation is
// available end to end. The other surfaces stay bare objects.
func TestServerDiscoveryAdvertisesInputRequests(t *testing.T) {
	t.Parallel()
	rc := mrtrRoutable(mrtrRegistry(t, registrydomain.MCPProtocolModeModern))

	advertised := serverDiscoveryResult(rc, true)["capabilities"].(map[string]any)
	require.Equal(t, map[string]any{"inputRequests": map[string]any{}}, advertised["tools"])
	require.Empty(t, advertised["prompts"])
	require.Empty(t, advertised["resources"])

	hidden := serverDiscoveryResult(rc, false)["capabilities"].(map[string]any)
	require.Empty(t, hidden["tools"])
}
