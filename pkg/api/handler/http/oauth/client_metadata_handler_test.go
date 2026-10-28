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
	"encoding/json"
	"net/http/httptest"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func clientMetadataApp(publicBaseURL string) *fiber.App {
	app := fiber.New()
	app.Get(ClientMetadataPath, NewClientMetadataHandler(publicBaseURL, "TrustGate MCP Gateway").Handle)
	return app
}

// The document names the URL it was fetched from as its client_id and the
// connect callback for the same provider, on the configured public origin.
func TestClientMetadataHandler_ServesTheProviderDocument(t *testing.T) {
	t.Parallel()
	app := clientMetadataApp("https://oauth.mcp.example/")

	req := httptest.NewRequest(fiber.MethodGet, "/oauth/client-metadata/io.aircall/mcp", nil)
	req.Host = "oauth.mcp.example"
	res, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, res.StatusCode)
	require.Contains(t, res.Header.Get(fiber.HeaderContentType), "application/json")
	require.Equal(t, "public, max-age=3600", res.Header.Get(fiber.HeaderCacheControl))

	var doc appoauth.ClientMetadataDocument
	require.NoError(t, json.NewDecoder(res.Body).Decode(&doc))
	require.Equal(t, "https://oauth.mcp.example/oauth/client-metadata/io.aircall/mcp", doc.ClientID)
	require.Equal(t, []string{"https://oauth.mcp.example/oauth/callback/io.aircall/mcp"}, doc.RedirectURIs)
	require.Equal(t, "TrustGate MCP Gateway", doc.ClientName)
	require.Equal(t, "none", doc.TokenEndpointAuthMethod)
}

// Without a configured public origin the request origin is the base, as it is
// for the connect redirect URI.
func TestClientMetadataHandler_FallsBackToTheRequestOrigin(t *testing.T) {
	t.Parallel()
	app := clientMetadataApp("")

	req := httptest.NewRequest(fiber.MethodGet, "/oauth/client-metadata/linear-mcp", nil)
	req.Host = "acme.mcp.example"
	res, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, res.StatusCode)
	var doc appoauth.ClientMetadataDocument
	require.NoError(t, json.NewDecoder(res.Body).Decode(&doc))
	require.Equal(t, "http://acme.mcp.example/oauth/client-metadata/linear-mcp", doc.ClientID)
	require.Equal(t, []string{"http://acme.mcp.example/oauth/callback/linear-mcp"}, doc.RedirectURIs)
}

// An escaped spelling is not a client_id the gateway hands out: answering it
// would publish a document whose client_id is not the URL that was fetched.
func TestClientMetadataHandler_UnknownShapesAreNotFound(t *testing.T) {
	t.Parallel()
	app := clientMetadataApp("https://oauth.mcp.example")
	for _, path := range []string{
		"/oauth/client-metadata/",
		"/oauth/client-metadata/io.aircall%2Fmcp",
		"/oauth/client-metadata/io.aircall/",
		"/oauth/client-metadata/a%20b",
	} {
		res, err := app.Test(httptest.NewRequest(fiber.MethodGet, path, nil))
		require.NoError(t, err)
		require.Equal(t, fiber.StatusNotFound, res.StatusCode, path)
	}
}
