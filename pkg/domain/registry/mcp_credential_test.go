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

package registry_test

import (
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

func forwardedRegistry(t *testing.T, name, url, provider, resource string) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), name, "", &domain.MCPTarget{
		URL:  url,
		Code: "app.linear/mcp",
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeForwarded,
			Provider:     provider,
			Resource:     resource,
			ClientID:     "cid",
			AuthorizeURL: "https://idp.example.com/a",
			TokenURL:     "https://idp.example.com/t",
		},
	})
	require.NoError(t, err)
	return reg
}

func TestForwardedVaultProvider_SeparatesInstancesOfOneCode(t *testing.T) {
	t.Parallel()
	// Two instances of the same catalog code, each pointing at its own
	// deployment: one credential per workspace, so the token minted for one is
	// never forwarded to the other.
	develop := forwardedRegistry(t, "Linear Develop", "https://develop.linear.app/mcp", "app.linear/mcp", "")
	prod := forwardedRegistry(t, "Linear Prod", "https://prod.linear.app/mcp", "app.linear/mcp", "")

	require.NotEqual(t, domain.ForwardedVaultProvider(develop), domain.ForwardedVaultProvider(prod))
	for _, reg := range []*domain.Registry{develop, prod} {
		key := domain.ForwardedVaultProvider(reg)
		require.True(t, strings.HasPrefix(key, "app.linear/mcp|"), "key %q keeps the provider readable", key)
		require.Equal(t, "app.linear/mcp", domain.ForwardedVaultProviderName(key))
	}
}

func TestForwardedVaultProvider_SharesOneDeployment(t *testing.T) {
	t.Parallel()
	// Same deployment, two registries (different toolkits, say): one credential,
	// so the user connects once and both instances work.
	full := forwardedRegistry(t, "Linear", "https://mcp.linear.app/mcp", "app.linear/mcp", "")
	readOnly := forwardedRegistry(t, "Linear read-only", "https://mcp.linear.app/mcp/", "app.linear/mcp", "")

	require.Equal(t, domain.ForwardedVaultProvider(full), domain.ForwardedVaultProvider(readOnly))
}

func TestForwardedVaultProvider_PrefersTheDeclaredResource(t *testing.T) {
	t.Parallel()
	// The OAuth resource is what the token is issued for, so it wins over the
	// URL the gateway happens to dial.
	viaAlias := forwardedRegistry(t, "Linear alias", "https://alias.linear.app/mcp", "app.linear/mcp", "https://mcp.linear.app/mcp")
	direct := forwardedRegistry(t, "Linear", "https://mcp.linear.app/mcp", "app.linear/mcp", "https://MCP.linear.app:443/mcp/")

	require.Equal(t, domain.ForwardedVaultProvider(viaAlias), domain.ForwardedVaultProvider(direct))
}

func TestForwardedVaultProvider_IgnoresWhatDoesNotForward(t *testing.T) {
	t.Parallel()
	reg, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), "static", "", &domain.MCPTarget{
		URL:  "https://mcp.linear.app/mcp",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer k"},
	})
	require.NoError(t, err)

	require.Empty(t, domain.ForwardedVaultProvider(reg))
	require.Empty(t, domain.ForwardedCredentialResource(reg))
	require.Nil(t, reg.ForwardedAuth())
}

func TestForwardedVaultProviderName_LeavesAPlainKeyAlone(t *testing.T) {
	t.Parallel()
	// A URL-variable key carries no fingerprint and must not be truncated into
	// something that could collide with a provider name.
	key := domain.URLVariableVaultProvider("com.snowflake/mcp", "account_url")
	require.Equal(t, key, domain.ForwardedVaultProviderName(key))
}
