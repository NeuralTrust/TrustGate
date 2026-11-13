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

package catalog

import (
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/gofiber/fiber/v2"
)

// grantTypeClientCredentials is the catalog grant with no user redirect.
const grantTypeClientCredentials = "client_credentials"

type ListMCPServersHandler struct {
	catalog appcatalog.MCPServerCatalog
	// oauthPublicBaseURL is the connect redirect origin
	// (MCP_OAUTH_PUBLIC_BASE_URL). Empty means each connect uses the host it
	// was requested on, which this admin API cannot know.
	oauthPublicBaseURL string
}

// NewListMCPServersHandler builds the catalog listing. oauthPublicBaseURL is
// MCP_OAUTH_PUBLIC_BASE_URL; when set, every OAuth server that redirects a user
// is listed with the exact redirect URI to register with the vendor.
func NewListMCPServersHandler(catalog appcatalog.MCPServerCatalog, oauthPublicBaseURL string) *ListMCPServersHandler {
	return &ListMCPServersHandler{
		catalog:            catalog,
		oauthPublicBaseURL: strings.TrimRight(strings.TrimSpace(oauthPublicBaseURL), "/"),
	}
}

// MCPServerListing is one catalog server as the admin console reads it.
type MCPServerListing struct {
	domain.MCPServer
	// OAuthRedirectURI is the redirect URI the gateway sends when a user
	// connects this server, for an admin registering a manual OAuth client.
	// Omitted when the server has no user redirect, or when this deployment
	// sets no fixed connect origin (MCP_OAUTH_PUBLIC_BASE_URL).
	OAuthRedirectURI string `json:"oauth_redirect_uri,omitempty"`
}

type ListMCPServersResponse struct {
	MCPServers []MCPServerListing `json:"mcp_servers"`
}

// Handle godoc
// @Summary      List the MCP servers catalog
// @Description  Returns the curated catalog of well-known remote MCP servers, used to prefill MCP registry creation.
// @Tags         catalog
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  ListMCPServersResponse
// @Failure      401  {object}  httpio.ErrorBody
// @Router       /v1/mcp-servers-catalog [get]
func (h *ListMCPServersHandler) Handle(c *fiber.Ctx) error {
	servers := h.catalog.ListMCPServers()
	out := make([]MCPServerListing, 0, len(servers))
	for _, server := range servers {
		out = append(out, MCPServerListing{
			MCPServer:        server,
			OAuthRedirectURI: h.redirectURI(server),
		})
	}
	return httpio.WriteOK(c, ListMCPServersResponse{MCPServers: out})
}

// redirectURI is the connect redirect URI for a server whose OAuth sends the
// user to the vendor. The connect flow keys it on the registry's provider,
// which a catalog install sets to the catalog code.
func (h *ListMCPServersHandler) redirectURI(server domain.MCPServer) string {
	if h.oauthPublicBaseURL == "" || server.OAuth == nil || server.OAuth.GrantType == grantTypeClientCredentials {
		return ""
	}
	code := strings.TrimSpace(server.Code)
	if code == "" {
		return ""
	}
	return appoauth.ConnectCallbackURL(h.oauthPublicBaseURL, code)
}
