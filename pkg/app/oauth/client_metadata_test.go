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

package oauth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The client_id EnsureClient derives from a connect redirect URI is the URL the
// gateway publishes, and the document there lists that same redirect URI.
func TestClientMetadataDocument_RoundTripsTheConnectRedirect(t *testing.T) {
	t.Parallel()
	const base = "https://oauth.mcp.example"
	redirect := connectCallbackURL(base, "io.aircall/mcp")

	clientID, ok := ClientMetadataURLForRedirect(redirect)
	require.True(t, ok)
	require.Equal(t, base+"/oauth/client-metadata/io.aircall/mcp", clientID)

	doc, ok := NewClientMetadataDocument(base+"/", "io.aircall/mcp", "TrustGate MCP Gateway")
	require.True(t, ok)
	require.Equal(t, ClientMetadataDocument{
		ClientID:                clientID,
		ClientName:              "TrustGate MCP Gateway",
		RedirectURIs:            []string{redirect},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}, doc)
}

func TestClientMetadataURLForRedirect_OnlyForAnHTTPSConnectCallback(t *testing.T) {
	t.Parallel()
	for _, redirect := range []string{
		"",
		"http://oauth.mcp.example/oauth/callback/io.aircall/mcp",
		"https://oauth.mcp.example/oauth/callback",
		"https://oauth.mcp.example/oauth/callback/",
		"https://oauth.mcp.example/oauth/connect/io.aircall/mcp",
		"https://oauth.mcp.example/oauth/callback/io.aircall%2Fmcp",
		"https://oauth.mcp.example/oauth/callback/io.aircall/mcp?x=1",
		"https://oauth.mcp.example/oauth/callback/io.aircall/mcp#x",
		"https://user@oauth.mcp.example/oauth/callback/io.aircall/mcp",
		"https://oauth.mcp.example/oauth/callback/../register",
		"https:///oauth/callback/io.aircall/mcp",
	} {
		_, ok := ClientMetadataURLForRedirect(redirect)
		require.False(t, ok, redirect)
	}
}

func TestNewClientMetadataDocument_RefusesProvidersTheURLCannotCarry(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{"", "/io.aircall", "io.aircall/", "io//mcp", "a/../b", ".", "my provider", "a%2Fb", "a?b", "a#b", "é"} {
		_, ok := NewClientMetadataDocument("https://oauth.mcp.example", provider, "TrustGate MCP Gateway")
		require.False(t, ok, provider)
	}
	_, ok := NewClientMetadataDocument("", "io.aircall/mcp", "TrustGate MCP Gateway")
	require.False(t, ok, "no base URL")

	for _, provider := range []string{"io.aircall/mcp", "linear-mcp", "app.linear/mcp", "a_b~c"} {
		_, ok := NewClientMetadataDocument("https://oauth.mcp.example", provider, "TrustGate MCP Gateway")
		require.True(t, ok, provider)
	}
}
