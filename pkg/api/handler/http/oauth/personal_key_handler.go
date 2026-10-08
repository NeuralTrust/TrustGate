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
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const (
	personalKeyCookieSecureName = "__Host-tg_personal_key_"
	personalKeyCookiePlainName  = "tg_personal_key_"
)

// PersonalKeyHandler serves the MCP Store's personal key page. A Store link
// carries a ticket; the browser holding it signs in through the gateway's
// default identity provider, and only a browser that came back as the link's
// owner sees the page. See appoauth.PersonalKeyPages.
type PersonalKeyHandler struct {
	pages    appoauth.PersonalKeyPages
	gateways resolver.GatewayResolver
	cookies  FlowCookies
}

func NewPersonalKeyHandler(pages appoauth.PersonalKeyPages, gateways resolver.GatewayResolver, cookies FlowCookies) *PersonalKeyHandler {
	return &PersonalKeyHandler{pages: pages, gateways: gateways, cookies: cookies}
}

// Page shows the page, or sends a browser that has not signed in for this
// link to do so first.
func (h *PersonalKeyHandler) Page(c *fiber.Ctx) error {
	setPersonalKeyResponsePolicies(c)
	ticket := c.Query("ticket")
	ctx := resolver.WithResolvedGateway(c, h.gateways)
	view, location, err := h.pages.Open(ctx, c.BaseURL(), ticket, c.Cookies(h.cookieName(c, ticket)))
	if err != nil {
		return h.pageError(c, err)
	}
	if location != "" {
		// The gateway's OAuth callback only redeems a sign-in started in the
		// browser that comes back to it.
		if u, perr := url.Parse(location); perr == nil {
			h.cookies.setStateCookie(c, u.Query().Get("state"))
		}
		return c.Redirect(location, fiber.StatusFound)
	}
	return renderPersonalKeyPage(c, view)
}

// Return takes the browser back from signing in and binds it to the link.
func (h *PersonalKeyHandler) Return(c *fiber.Ctx) error {
	setPersonalKeyResponsePolicies(c)
	ticket := c.Query("ticket")
	session, err := h.pages.Return(c.UserContext(), ticket, c.Query(appoauth.BrowserProofParam))
	if err != nil {
		return h.pageError(c, err)
	}
	c.Cookie(&fiber.Cookie{
		Name:     h.cookieName(c, ticket),
		Value:    session,
		Path:     "/",
		MaxAge:   int(appoauth.PersonalKeyTicketTTL / time.Second),
		Secure:   h.cookies.secure(c),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
	return c.Redirect(appoauth.PersonalKeyPagePath+"?"+url.Values{"ticket": {ticket}}.Encode(), fiber.StatusSeeOther)
}

// Act does what the page's form asked: create, rotate or revoke.
func (h *PersonalKeyHandler) Act(c *fiber.Ctx) error {
	setPersonalKeyResponsePolicies(c)
	// The form posts to its own page; a post from anywhere else is not the
	// person pressing the button. Browsers that send Fetch Metadata say so.
	if site := c.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return renderPersonalKeyProblem(c, fiber.StatusForbidden, personalKeyProblem{
			Title: "This request did not come from the page",
			Body:  "Open the link your assistant gave you and use the buttons on that page.",
		})
	}
	if !isFormURLEncoded(c.Get(fiber.HeaderContentType)) {
		return fiber.NewError(fiber.StatusUnsupportedMediaType, "expected application/x-www-form-urlencoded")
	}
	form, err := url.ParseQuery(string(c.Body()))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "malformed form body")
	}
	ticket := c.Query("ticket")
	view, err := h.pages.Act(c.UserContext(), ticket, c.Cookies(h.cookieName(c, ticket)), form.Get("csrf"), form.Get("action"))
	if err != nil {
		return h.pageError(c, err)
	}
	return renderPersonalKeyPage(c, view)
}

func (h *PersonalKeyHandler) pageError(c *fiber.Ctx, err error) error {
	var wrong *appoauth.PersonalKeyWrongAccountError
	var limited *appoauth.ConnectRateLimitExceeded
	switch {
	case errors.Is(err, appoauth.ErrPersonalKeyLinkGone):
		return renderPersonalKeyProblem(c, fiber.StatusGone, personalKeyProblem{
			Title: "This link has expired",
			Body:  "Links to your personal key last 15 minutes and open once. Ask your assistant for a new one.",
		})
	case errors.As(err, &wrong):
		return renderPersonalKeyProblem(c, fiber.StatusForbidden, personalKeyProblem{
			Title:  "This link is for another account",
			Body:   "This browser is signed in to NeuralTrust as a different person than the one the link was made for. Sign in to the NeuralTrust console as yourself, then open the link again.",
			Signed: wrong.Email,
		})
	case errors.Is(err, appoauth.ErrPersonalKeyNotSignedIn), errors.Is(err, appoauth.ErrBrowserProof):
		return renderPersonalKeyProblem(c, fiber.StatusForbidden, personalKeyProblem{
			Title: "Sign in again",
			Body:  "Your sign-in for this page could not be confirmed. Open the link your assistant gave you again.",
		})
	case errors.As(err, &limited):
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(int(limited.RetryAfter/time.Second)))
		return renderPersonalKeyProblem(c, fiber.StatusTooManyRequests, personalKeyProblem{
			Title: "Too many changes",
			Body:  "Your personal key was changed too many times in the last hour. Try again later.",
		})
	case errors.Is(err, appoauth.ErrPersonalKeyUnknownAction):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	var oe *appoauth.OAuthError
	if errors.As(err, &oe) {
		return writeOAuthError(c, err)
	}
	return err
}

// cookieName is per link, so two links open side by side keep their own
// sign-in.
func (h *PersonalKeyHandler) cookieName(c *fiber.Ctx, ticket string) string {
	sum := sha256.Sum256([]byte(ticket))
	suffix := hex.EncodeToString(sum[:8])
	if h.cookies.secure(c) {
		return personalKeyCookieSecureName + suffix
	}
	return personalKeyCookiePlainName + suffix
}

func setPersonalKeyResponsePolicies(c *fiber.Ctx) {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set("Referrer-Policy", "no-referrer")
	// A page that shows a secret is never framed.
	c.Set("Content-Security-Policy", "frame-ancestors 'none'")
}
