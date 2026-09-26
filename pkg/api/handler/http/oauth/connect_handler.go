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
	"errors"
	"strings"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// Provider keys can contain slashes (e.g. "app.linear/mcp"), so these routes
// use a greedy wildcard segment instead of a single-segment :provider param.
const (
	ConnectStartPath    = "/oauth/connect/*"
	ConnectCallbackPath = "/oauth/callback/*"
	DisconnectPath      = "/oauth/disconnect/*"
	BrandAssetPath      = "/oauth/brands/*"
)

type ConnectHandler struct {
	connect            appoauth.ConnectService
	catalog            appcatalog.MCPServerCatalog
	oauthPublicBaseURL string
}

// NewConnectHandler builds the MCP upstream-connect OAuth handlers.
// oauthPublicBaseURL, when non-empty, is used as the redirect_uri origin for
// authorize and code exchange instead of the request Host (see
// MCP_OAUTH_PUBLIC_BASE_URL). Empty keeps per-request BaseURL behavior.
func NewConnectHandler(
	connect appoauth.ConnectService,
	catalog appcatalog.MCPServerCatalog,
	oauthPublicBaseURL string,
) *ConnectHandler {
	return &ConnectHandler{
		connect:            connect,
		catalog:            catalog,
		oauthPublicBaseURL: strings.TrimRight(strings.TrimSpace(oauthPublicBaseURL), "/"),
	}
}

func (h *ConnectHandler) Page(c *fiber.Ctx) error {
	ticket := c.Query("ticket")
	if ticket == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "missing ticket: re-run the tool call to get a fresh connect link")
	}
	return h.showPage(c, ticket, "")
}

func (h *ConnectHandler) Start(c *fiber.Ctx) error {
	location, err := h.connect.Start(c.UserContext(), h.connectBaseURL(c), c.Query("ticket"), providerParam(c))
	if err != nil {
		return h.pageError(c, err)
	}
	return c.Redirect(location, fiber.StatusFound)
}

func (h *ConnectHandler) Callback(c *fiber.Ctx) error {
	ticketID, err := h.connect.Callback(
		c.UserContext(), h.connectBaseURL(c), providerParam(c),
		c.Query("state"), c.Query("code"), c.Query("error"), c.Query("error_description"),
	)
	if err != nil {
		if ticketID == "" {
			return h.pageError(c, err)
		}
		return h.showPage(c, ticketID, callbackFlash(err))
	}
	return h.showPage(c, ticketID, "")
}

// callbackFlash turns an error the upstream identity provider sent back on the
// redirect into something the person signing in can act on. Those errors arrive
// as a bare RFC 6749 code, often without a description, and showing
// "invalid_target" on its own tells them nothing. The code stays in the message
// so an operator can still tell the failures apart.
func callbackFlash(err error) string {
	var oerr *appoauth.OAuthError
	if !errors.As(err, &oerr) {
		return err.Error()
	}
	var msg string
	switch oerr.Code {
	case "access_denied":
		msg = "Sign-in was cancelled or access was not granted. Try again to connect your account."
	case "invalid_target", "invalid_scope", "invalid_request", "unauthorized_client", "unsupported_response_type":
		msg = "The provider rejected the sign-in request. Try again, and if it keeps failing, ask your administrator to check this connector's OAuth configuration."
	case "server_error", "temporarily_unavailable":
		msg = "The provider could not complete the sign-in right now. Wait a moment and try again."
	default:
		msg = "Sign-in with the provider failed. Try again, and if it keeps failing, contact your administrator."
	}
	detail := oerr.Code
	if oerr.Description != "" {
		detail += ": " + oerr.Description
	}
	return msg + " (" + detail + ")"
}

func (h *ConnectHandler) Disconnect(c *fiber.Ctx) error {
	ticket := c.Query("ticket")
	if err := h.connect.Disconnect(c.UserContext(), ticket, providerParam(c)); err != nil {
		return h.pageError(c, err)
	}
	return h.showPage(c, ticket, "")
}

// connectBaseURL is the origin embedded in upstream IdP redirect_uri values.
// Prefer the configured platform public base so multi-tenant cloud can share
// one OAuth app allowlist; fall back to the request origin for self-hosted.
func (h *ConnectHandler) connectBaseURL(c *fiber.Ctx) string {
	if h.oauthPublicBaseURL != "" {
		return h.oauthPublicBaseURL
	}
	return c.BaseURL()
}

func providerParam(c *fiber.Ctx) string {
	return strings.TrimPrefix(c.Params("*"), "/")
}

func (h *ConnectHandler) showPage(c *fiber.Ctx, ticket, flash string) error {
	page, err := h.connect.Page(c.UserContext(), ticket)
	if err != nil {
		return h.pageError(c, err)
	}
	return renderConnectPage(c, page, ticket, flash, h.catalog)
}

func (h *ConnectHandler) pageError(c *fiber.Ctx, err error) error {
	if errors.Is(err, appoauth.ErrTicketNotFound) {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	if errors.Is(err, appoauth.ErrProviderNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	return err
}
