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

package oauth_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

// vaultKey is where a fixture's forwarded credential lives: the provider plus a
// fingerprint of the upstream it points at. Derived through the production
// helper on purpose — a test that hardcoded the composed key would keep passing
// if the two sides of it ever drifted apart.
func vaultKey(t *testing.T, provider, upstreamURL string) string {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(ids.New[ids.GatewayKind](), "key-probe", "", &registrydomain.MCPTarget{
		URL: upstreamURL,
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     provider,
			ClientID:     "cid",
			AuthorizeURL: "https://idp.example.com/a",
			TokenURL:     "https://idp.example.com/t",
		},
	})
	require.NoError(t, err)
	return registrydomain.ForwardedVaultProvider(reg)
}
