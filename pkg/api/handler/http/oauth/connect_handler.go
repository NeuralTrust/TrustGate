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
	// ConnectFinishPath is an exact path under ConnectStartPath, so it has to
	// be routed ahead of it.
	ConnectFinishPath = appoauth.ConnectFinishPath
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

// ConnectFlow is the connect service as the connect pages use it.
type ConnectFlow interface {
	Page(ctx context.Context, ticketID string) (*appoauth.ConnectPage, error)
	StartOrigin(ctx context.Context, callbackOrigin, origin, ticketID string) (string, error)
	Start(ctx context.Context, baseURL, startOrigin, ticketID, provider, instanceID string) (*appoauth.ConnectStart, error)
	ReceiveCallback(ctx context.Context, provider, state, code, errCode, errDesc string) (string, error)
	TakeFinish(ctx context.Context, token string) (*appoauth.ConnectFinish, error)
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
	if moved, err := h.toCallbackOrigin(c, ticket); moved || err != nil {
		return err
	}
	return h.showPage(c, ticket, "")
}

// toCallbackOrigin sends a connect page requested on a host connections are
// not started from (a gateway's custom domain) to the same page on the
// callback origin, where the connection is then started and finished. It
// reports whether it did; any error has already been answered.
func (h *ConnectHandler) toCallbackOrigin(c *fiber.Ctx, ticket string) (bool, error) {
	callback := h.connectBaseURL(c)
	if strings.EqualFold(callback, c.BaseURL()) {
		return false, nil
	}
	_, err := h.connect.StartOrigin(c.UserContext(), callback, c.BaseURL(), ticket)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, appoauth.ErrStartOriginNotServed):
		c.Set(fiber.HeaderCacheControl, "no-store")
		return true, c.Redirect(callback+c.OriginalURL(), fiber.StatusFound)
	default:
		return false, h.pageError(c, err)
	}
}

// Confirm answers a link that opens a provider connection directly. It names
// who the account will be linked to and continues only on a POST, so following
// a link never connects an account by itself.
func (h *ConnectHandler) Confirm(c *fiber.Ctx) error {
	ticket := c.Query("ticket")
	if ticket == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "missing ticket: re-run the tool call to get a fresh connect link")
	}
	if moved, err := h.toCallbackOrigin(c, ticket); moved || err != nil {
		return err
	}
	page, err := h.connect.Page(c.UserContext(), ticket)
	if err != nil {
		return h.pageError(c, err)
	}
	provider := providerParam(c)
	row, ok := confirmRow(page, provider, c.Query("instance"))
	if !ok {
		return h.pageError(c, appoauth.ErrProviderNotFound)
	}
	if row.Shared {
		return h.pageError(c, appoauth.ErrSharedAccountNotYours)
	}
	return renderConnectConfirmPage(c, connectConfirmView{
		Owner:        ownerOf(page.Principal),
		ConsumerPath: page.ConsumerPath,
		AccountRef:   linkedAccount(row),
		FormAction:   connectStartAction(provider, ticket, row.Instance),
	}, row, h.catalog)
}

// Start begins a provider connection from a page of this gateway. It sets the
// flow's cookie on this host before sending the browser to the provider, and
// only this host finishes the flow (see Finish), so it completes only in the
// browser that started it.
func (h *ConnectHandler) Start(c *fiber.Ctx) error {
	if !sentFromOwnPage(c) {
		return h.pageError(c, errConnectNotFromPage)
	}
	if !cookieTransportAllowed(c, h.connectBaseURL(c)) {
		return h.pageError(c, errConnectNeedsHTTPS)
	}
	started, err := h.connect.Start(
		c.UserContext(), h.connectBaseURL(c), c.BaseURL(), c.Query("ticket"), providerParam(c), c.Query("instance"),
	)
	if err != nil {
		return h.pageError(c, err)
	}
	setConnectCookie(c, started.State)
	// Never cache or prefetch the start: each one mints a new state upstream.
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Redirect(started.Location, fiber.StatusFound)
}

// Callback receives the provider's redirect on the callback origin. It does
// not complete the connection: it hands the result to the origin the flow was
// started from, whose cookie decides whether this browser may finish it.
func (h *ConnectHandler) Callback(c *fiber.Ctx) error {
	location, err := h.connect.ReceiveCallback(
		c.UserContext(), providerParam(c),
		c.Query("state"), c.Query("code"), c.Query("error"), c.Query("error_description"),
	)
	if err != nil {
		return h.pageError(c, err)
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Redirect(location, fiber.StatusFound)
}

// Finish completes a connection on the origin it was started from, in the
// browser holding that flow's cookie. Any other browser is refused and the
// started authorization is left as it was.
func (h *ConnectHandler) Finish(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	if !cookieTransportAllowed(c, h.connectBaseURL(c)) {
		return h.pageError(c, errConnectNeedsHTTPS)
	}
	finish, err := h.connect.TakeFinish(c.UserContext(), c.Query("f"))
	if err != nil {
		return h.pageError(c, err)
	}
	if !connectBoundTo(c, finish.State) {
		return h.pageError(c, errConnectStartedElsewhere)
	}
	clearConnectCookie(c, finish.State)
	ticketID, err := h.connect.Callback(
		c.UserContext(), h.connectBaseURL(c), finish.Provider,
		finish.State, finish.Code, finish.ErrCode, finish.ErrDesc,
	)
	if err != nil {
		if ticketID == "" {
			return h.pageError(c, err)
		}
		return h.showPage(c, ticketID, callbackFlash(err))
	}
	page, err := h.connect.Page(c.UserContext(), ticketID)
	if err != nil {
		return h.pageError(c, err)
	}
	return renderConnectPageAfter(c, page, ticketID, "", true, h.catalog)
}

// confirmRow is the row a connect for this provider acts on, picked the way
// the service picks the instance: the one named, else the one the ticket is
// pinned to, else the first of the provider.
func confirmRow(page *appoauth.ConnectPage, provider, instance string) (appoauth.ProviderStatus, bool) {
	for _, want := range []string{instance, page.Instance} {
		if want == "" {
			continue
		}
		for _, row := range page.Providers {
			if row.Provider == provider && row.Instance == want {
				return row, true
			}
		}
	}
	for _, row := range page.Providers {
		if row.Provider == provider {
			return row, true
		}
	}
	return appoauth.ProviderStatus{}, false
}

func linkedAccount(row appoauth.ProviderStatus) string {
	if !row.Linked {
		return ""
	}
	if row.AccountRef != "" {
		return row.AccountRef
	}
	return "an account"
}

// connectStartAction is the form action that starts a connection. The provider
// id is escaped segment by segment because it carries slashes.
func connectStartAction(provider, ticket, instance string) string {
	segments := strings.Split(provider, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	q := url.Values{"ticket": {ticket}}
	if instance != "" {
		q.Set("instance", instance)
	}
	return strings.TrimSuffix(ConnectStartPath, "*") + strings.Join(segments, "/") + "?" + q.Encode()
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
	if errors.Is(err, appoauth.ErrConnectFinishNotFound) {
		return errConnectFinishGone
	}
	if errors.Is(err, appoauth.ErrStartOriginNotServed) {
		return errConnectStartHost
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
