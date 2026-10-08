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
	"net"
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

func connectCookieName(c *fiber.Ctx, state string) string {
	suffix := connectBinding(state)[:connectCookieNameHexLen]
	if c.Secure() {
		return connectCookieSecurePrefix + suffix
	}
	return connectCookiePlainPrefix + suffix
}

func setConnectCookie(c *fiber.Ctx, state string) {
	c.Cookie(&fiber.Cookie{
		Name:     connectCookieName(c, state),
		Value:    connectBinding(state),
		Path:     "/",
		MaxAge:   int(connectCookieMaxAge / time.Second),
		Secure:   c.Secure(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// clearConnectCookie expires a flow's cookie once it has finished. The
// attributes mirror setConnectCookie, or a browser keeps the __Host- cookie.
func clearConnectCookie(c *fiber.Ctx, state string) {
	c.Cookie(&fiber.Cookie{
		Name:     connectCookieName(c, state),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   c.Secure(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// connectBoundTo reports whether this browser holds the cookie set when the
// flow for state was started.
func connectBoundTo(c *fiber.Ctx, state string) bool {
	if state == "" {
		return false
	}
	cookie := c.Cookies(connectCookieName(c, state))
	if cookie == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie), []byte(connectBinding(state))) == 1
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
		return origin != "" && strings.EqualFold(origin, c.BaseURL())
	default:
		return false
	}
}

// cookieTransportAllowed reports whether the flow's cookie can be trusted on
// this request. Over https it is a __Host- cookie, which no other host can
// set. A plain-http request is accepted where the whole plane runs on http
// (callbackOrigin is http) and on a loopback host; on an https deployment it is
// refused, since a cookie without the __Host- prefix can be set by a sibling
// host.
func cookieTransportAllowed(c *fiber.Ctx, callbackOrigin string) bool {
	if c.Secure() || !strings.HasPrefix(strings.ToLower(callbackOrigin), "https://") {
		return true
	}
	host := c.Hostname()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

var (
	errConnectStartedElsewhere = fiber.NewError(fiber.StatusBadRequest,
		"This sign-in was started in another browser. Start again from the link you were given.")
	errConnectNotFromPage = fiber.NewError(fiber.StatusForbidden,
		"Open the link you were given and continue from the page it shows.")
	errConnectFinishGone = fiber.NewError(fiber.StatusBadRequest,
		"This sign-in link was already used or has expired. Start again from the link you were given.")
	errConnectNeedsHTTPS = fiber.NewError(fiber.StatusBadRequest,
		"Connections need a secure (https) address. Open the link you were given.")
	errConnectStartHost = fiber.NewError(fiber.StatusBadRequest,
		"Connections cannot be started from this address. Open the link you were given.")
)
