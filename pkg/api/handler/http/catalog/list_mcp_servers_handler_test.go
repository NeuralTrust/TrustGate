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

package catalog_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	cataloghttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/catalog"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type listedServer struct {
	Code             string `json:"code"`
	OAuthRedirectURI string `json:"oauth_redirect_uri"`
	OAuth            *struct {
		GrantType string `json:"grant_type"`
	} `json:"oauth"`
}

func listMCPServers(t *testing.T, oauthPublicBaseURL string) map[string]listedServer {
	t.Helper()
	cat, err := appcatalog.NewMCPServerCatalog(nil)
	require.NoError(t, err)
	app := fiber.New()
	app.Get("/v1/mcp-servers-catalog", cataloghttp.NewListMCPServersHandler(cat, oauthPublicBaseURL).Handle)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/mcp-servers-catalog", nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	var body struct {
		MCPServers []listedServer `json:"mcp_servers"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.NotEmpty(t, body.MCPServers)
	byCode := make(map[string]listedServer, len(body.MCPServers))
	for _, server := range body.MCPServers {
		byCode[server.Code] = server
	}
	return byCode
}

// The setup guide used to say "register {gatewayBaseUrl}/oauth/callback/…" and
// leave the admin to guess the host. In cloud the connect redirect is the fixed
// MCP_OAUTH_PUBLIC_BASE_URL, not the gateway host the console shows, so a
// guessed host fails at the vendor (AADSTS50011 for Outlook, ENG-3262).
func TestListMCPServersHandler_ListsTheConnectRedirectURI(t *testing.T) {
	t.Parallel()
	servers := listMCPServers(t, "https://gateway-mcp.example.com/")

	outlook, ok := servers["com.microsoft/outlook"]
	require.True(t, ok)
	require.Equal(t, "https://gateway-mcp.example.com/oauth/callback/com.microsoft/outlook", outlook.OAuthRedirectURI)

	for code, server := range servers {
		if server.OAuth == nil || server.OAuth.GrantType == "client_credentials" {
			require.Empty(t, server.OAuthRedirectURI, "%s has no user redirect", code)
		}
	}
}

// Without a fixed connect origin each connect uses the host it was requested
// on, so the listing has no single URI to give.
func TestListMCPServersHandler_OmitsRedirectURIWithoutAFixedOrigin(t *testing.T) {
	t.Parallel()
	for code, server := range listMCPServers(t, "") {
		require.Empty(t, server.OAuthRedirectURI, code)
	}
}
