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
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

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
	connect            ConnectFlow
	catalog            appcatalog.MCPServerCatalog
	oauthPublicBaseURL string
	// holdFor and holdEvery bound how long one request waits, before it
	// answers, for a server its ticket names to reach this plane (see
	// awaitServer). Fields rather than constants so tests need not sleep.
	holdFor   time.Duration
	holdEvery time.Duration
}

// connectPageHoldFor is how long a connect page waits for a server that is
// not on this plane yet before it shows the "getting ready" page instead.
// Config-sync brings a server shelved a moment ago within a few seconds, so
// the page that opens right after a connect is usually the real one.
const (
	connectPageHoldFor   = 5 * time.Second
	connectPageHoldEvery = 250 * time.Millisecond
)

type ConnectFlow interface {
	Page(ctx context.Context, ticketID string) (*appoauth.ConnectPage, error)
	Start(ctx context.Context, baseURL, ticketID, provider, instanceID string) (string, error)
	Callback(ctx context.Context, baseURL, provider, state, code, errCode, errDesc string) (string, error)
	Disconnect(ctx context.Context, ticketID, provider, instanceID string) error
}

// NewConnectHandler builds the MCP upstream-connect OAuth handlers.
// oauthPublicBaseURL, when non-empty, is used as the redirect_uri origin for
// authorize and code exchange instead of the request Host (see
// MCP_OAUTH_PUBLIC_BASE_URL). Empty keeps per-request BaseURL behavior.
func NewConnectHandler(
	connect ConnectFlow,
	catalog appcatalog.MCPServerCatalog,
	oauthPublicBaseURL string,
) *ConnectHandler {
	return &ConnectHandler{
		connect:            connect,
		catalog:            catalog,
		oauthPublicBaseURL: strings.TrimRight(strings.TrimSpace(oauthPublicBaseURL), "/"),
		holdFor:            connectPageHoldFor,
		holdEvery:          connectPageHoldEvery,
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
	location, err := h.connect.Start(
		c.UserContext(), h.connectBaseURL(c), c.Query("ticket"), providerParam(c), c.Query("instance"),
	)
	if err != nil {
		return h.pageError(c, err)
	}
	// Never cache or prefetch the start: each one mints a new state upstream.
	c.Set(fiber.HeaderCacheControl, "no-store")
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
		return h.showPage(c, ticketID, err.Error())
	}
	return h.showPage(c, ticketID, "")
}

func (h *ConnectHandler) Disconnect(c *fiber.Ctx) error {
	ticket := c.Query("ticket")
	if err := h.connect.Disconnect(c.UserContext(), ticket, providerParam(c), c.Query("instance")); err != nil {
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

// providerParam is the provider id from the wildcard route.
//
// A provider id carries a slash ("com.notion/mcp"), and both spellings of it
// reach here: the connect page links it raw, and a client that builds the URL
// properly percent-encodes it. Fiber matches the wildcard against the raw path
// and does not unescape, so decoding is this function's job - without it an
// escaped link resolves to a provider nothing is configured for.
func providerParam(c *fiber.Ctx) string {
	raw := strings.TrimPrefix(c.Params("*"), "/")
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		// A stray % is not an escape. Take the id as written rather than
		// refusing a provider that may well be named that.
		return raw
	}
	return decoded
}

func (h *ConnectHandler) showPage(c *fiber.Ctx, ticket, flash string) error {
	page, err := h.connect.Page(c.UserContext(), ticket)
	if err != nil {
		return h.pageError(c, err)
	}
	// A flash answers something the user just did; it is shown as it is.
	if flash == "" && connectWaitAttempt(c) < connectPageWaitAttempts {
		page = h.awaitServer(c.UserContext(), ticket, page)
	}
	return renderConnectPage(c, page, ticket, flash, h.catalog)
}

// awaitServer holds the answer, briefly, while the server a ticket names is
// not on this plane yet.
//
// Right after a connect the server was shelved on the control plane a moment
// ago, and config-sync usually brings it here within a few seconds. Answering
// at once showed "Getting … ready" and reloaded into the real page a moment
// later, which read as an error first. Waiting here instead means the page the
// user sees first is, in the common case, the one they came for; should the
// server still be missing, the page says it is getting ready and reloads, as
// before. A page the ticket does not scope to one server, or whose server is
// already here, is returned as it is.
func (h *ConnectHandler) awaitServer(ctx context.Context, ticket string, page *appoauth.ConnectPage) *appoauth.ConnectPage {
	if strings.TrimSpace(page.Code) == "" || len(providerRowsForPage(page)) > 0 || h.holdFor <= 0 {
		return page
	}
	deadline := time.NewTimer(h.holdFor)
	defer deadline.Stop()
	tick := time.NewTicker(h.holdEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return page
		case <-deadline.C:
			return page
		case <-tick.C:
			next, err := h.connect.Page(ctx, ticket)
			if err != nil {
				return page
			}
			page = next
			if len(providerRowsForPage(page)) > 0 {
				return page
			}
		}
	}
}

func (h *ConnectHandler) pageError(c *fiber.Ctx, err error) error {
	if errors.Is(err, appoauth.ErrTicketNotFound) {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	if errors.Is(err, appoauth.ErrProviderNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	// Not a fault of the request: the server holds one account for everyone and
	// this caller is not who connects it. Saying so beats a 500.
	if errors.Is(err, appoauth.ErrSharedAccountNotYours) {
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	// The upstream refused to register the gateway as an OAuth client: the
	// person connecting can do nothing about it, an operator has to. Name it as
	// the upstream's refusal instead of a 500, and keep its answer for them.
	if errors.Is(err, appoauth.ErrUpstreamRegistrationRejected) {
		return fiber.NewError(fiber.StatusBadGateway,
			"The provider refused to register this gateway as an OAuth app, so the account cannot be connected yet. "+
				"Ask your administrator to check this connector's configuration. Details: "+err.Error())
	}
	return err
}
