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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// ClientMetadataPath serves the gateway's client ID metadata document for one
// provider. Provider keys carry slashes, hence the wildcard.
const ClientMetadataPath = appoauth.ClientMetadataPathPrefix + "*"

// clientMetadataCacheControl lets the authorization server cache the document
// between connects; it changes only when the client name or base URL does.
const clientMetadataCacheControl = "public, max-age=3600"

// ClientMetadataHandler publishes the document an authorization server fetches
// when the gateway's client_id is a URL (see appoauth.ClientMetadataPathPrefix).
type ClientMetadataHandler struct {
	oauthPublicBaseURL string
	clientName         string
}

// NewClientMetadataHandler builds the handler. oauthPublicBaseURL is the
// connect redirect origin (MCP_OAUTH_PUBLIC_BASE_URL), empty for the request
// origin, as for ConnectHandler; clientName is the name the registrar
// registers with.
func NewClientMetadataHandler(oauthPublicBaseURL, clientName string) *ClientMetadataHandler {
	return &ClientMetadataHandler{
		oauthPublicBaseURL: strings.TrimRight(strings.TrimSpace(oauthPublicBaseURL), "/"),
		clientName:         clientName,
	}
}

// Handle answers the document for the provider in the path. The provider is
// read from the request path as written, not from the route wildcard (which
// drops a trailing slash) and not unescaped: the client_id in the document has
// to be the URL that was fetched, and no other spelling is a URL the gateway
// hands out.
func (h *ClientMetadataHandler) Handle(c *fiber.Ctx) error {
	base := h.oauthPublicBaseURL
	if base == "" {
		base = c.BaseURL()
	}
	provider, found := strings.CutPrefix(c.Path(), appoauth.ClientMetadataPathPrefix)
	if !found {
		return fiber.ErrNotFound
	}
	doc, ok := appoauth.NewClientMetadataDocument(base, provider, h.clientName)
	if !ok {
		return fiber.ErrNotFound
	}
	c.Set(fiber.HeaderCacheControl, clientMetadataCacheControl)
	return httpio.WriteOK(c, doc)
}
