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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/url"
	"strings"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// The connect cookie ties an upstream account connection to the browser that
// started it. Start sets it on the host the connection was started from; the
// provider callback hands the result back to that same host
// (appoauth.ConnectFinishPath), which completes the connection only when the
// cookie is there. Each flow has its own cookie, named after its state, so two
// connections started in one browser do not overwrite each other.
const (
	// connectCookieSecurePrefix carries the __Host- prefix, which browsers only
	// honour on a Secure cookie with Path=/ and no Domain.
	connectCookieSecurePrefix = "__Host-tg_connect_"
	// connectCookiePlainPrefix is used over plain http (local development and
	// self-hosted planes without TLS), where a __Host- cookie is rejected.
	connectCookiePlainPrefix = "tg_connect_"
	connectCookieNameHexLen  = 8
	connectCookieMaxAge      = appoauth.ConnectStateTTL
)

// headerSecFetchSite is the fetch metadata header a browser sends to say where
// a request came from.
const headerSecFetchSite = "Sec-Fetch-Site"

// connectBinding is the cookie value for a started authorization: a digest of
// its state, so the cookie never carries the state itself.
func connectBinding(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

// cookieSecure reports whether the flow cookie takes the Secure, __Host-
// form. It follows the MCP sign-in cookies (FlowCookies), so a proxy that ends
// TLS without forwarding the scheme still gets the __Host- form; a plane whose
// configured callback origin is plain http uses the plain form.
func (h *ConnectHandler) cookieSecure(c *fiber.Ctx) bool {
	if c.Secure() {
		return true
	}
	if strings.HasPrefix(strings.ToLower(h.oauthPublicBaseURL), "http://") {
		return false
	}
	return h.cookies.secure(c)
}

func (h *ConnectHandler) connectCookieName(c *fiber.Ctx, state string) string {
	suffix := connectBinding(state)[:connectCookieNameHexLen]
	if h.cookieSecure(c) {
		return connectCookieSecurePrefix + suffix
	}
	return connectCookiePlainPrefix + suffix
}

func (h *ConnectHandler) setConnectCookie(c *fiber.Ctx, state string) {
	secure := h.cookieSecure(c)
	c.Cookie(&fiber.Cookie{
		Name:     h.connectCookieName(c, state),
		Value:    connectBinding(state),
		Path:     "/",
		MaxAge:   int(connectCookieMaxAge / time.Second),
		Secure:   secure,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// clearConnectCookie expires a flow's cookie once it has finished. The
// attributes mirror setConnectCookie, or a browser keeps the __Host- cookie.
func (h *ConnectHandler) clearConnectCookie(c *fiber.Ctx, state string) {
	c.Cookie(&fiber.Cookie{
		Name:     h.connectCookieName(c, state),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   h.cookieSecure(c),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// connectBoundTo reports whether this browser holds the cookie set when the
// flow for state was started.
func (h *ConnectHandler) connectBoundTo(c *fiber.Ctx, state string) bool {
	if state == "" {
		return false
	}
	cookie := c.Cookies(h.connectCookieName(c, state))
	if cookie == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie), []byte(connectBinding(state))) == 1
}

// sameHost reports whether origin names the host and port this request was
// made to, whatever its scheme: behind a proxy that ends TLS without
// forwarding it, the request reads as http while the browser is on https.
func sameHost(origin string, c *fiber.Ctx) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	host := strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		host = strings.ToLower(u.Hostname())
	}
	return host == strings.ToLower(c.Hostname())
}

// sentFromOwnPage reports whether a browser submitted this request from a page
// of this same origin: by its fetch metadata, or, from a browser that sends
// none, by an Origin naming this origin. A request that carries neither is
// refused.
func sentFromOwnPage(c *fiber.Ctx) bool {
	switch c.Get(headerSecFetchSite) {
	case "same-origin":
		return true
	case "":
		origin := c.Get(fiber.HeaderOrigin)
		return origin != "" && origin != "null" && sameHost(origin, c)
	default:
		return false
	}
}

var (
	errConnectStartedElsewhere = fiber.NewError(fiber.StatusBadRequest,
		"This sign-in was started in another browser. Start again from the link you were given.")
	errConnectNotFromPage = fiber.NewError(fiber.StatusForbidden,
		"Open the link you were given and continue from the page it shows.")
	errConnectFinishGone = fiber.NewError(fiber.StatusBadRequest,
		"This sign-in link was already used or has expired. Start again from the link you were given.")
	errConnectStartHost = fiber.NewError(fiber.StatusBadRequest,
		"Connections cannot be started from this address. Open the link you were given.")
)
