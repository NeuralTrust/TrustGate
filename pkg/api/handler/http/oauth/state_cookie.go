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
	"crypto/subtle"
	"net/url"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// The state cookie binds a brokered authorization to the browser that started
// it. Without it the callback trusts whoever presents a valid `state`: an
// attacker who completes the IdP leg themselves can hand their state and code
// to a victim's browser (login CSRF), or inject their own code into a flow the
// victim started (authorization-code injection) — and since dynamic client
// registration is open and accepts any https redirect, the resulting session
// lands wherever the attacker registered. The IdP redirects back with a
// top-level navigation, which SameSite=Lax cookies accompany.
const (
	// stateCookieSecureName carries the __Host- prefix, which browsers only
	// honour on a Secure cookie with Path=/ and no Domain: it cannot be planted
	// by a sibling subdomain or overridden by a plain-http page.
	stateCookieSecureName = "__Host-oauth_state"
	// stateCookiePlainName is used over plain http (loopback development),
	// where a __Host- cookie would be rejected outright.
	stateCookiePlainName = "oauth_state"
	// stateCookieMaxAge matches how long a parked authorization survives.
	stateCookieMaxAge = 10 * time.Minute
)

func stateCookieName(c *fiber.Ctx) string {
	if c.Secure() {
		return stateCookieSecureName
	}
	return stateCookiePlainName
}

// setStateCookie remembers the gateway state of the IdP leg in the browser.
func setStateCookie(c *fiber.Ctx, state string) {
	c.Cookie(&fiber.Cookie{
		Name:     stateCookieName(c),
		Value:    state,
		Path:     "/",
		MaxAge:   int(stateCookieMaxAge / time.Second),
		Secure:   c.Secure(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// clearStateCookie expires the binding once the callback has consumed it. The
// attributes must mirror setStateCookie or a browser will not match the
// __Host- cookie it is meant to delete.
func clearStateCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     stateCookieName(c),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   c.Secure(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// gatewayStateOf extracts the state the proxy minted for the IdP leg from the
// redirect it produced. A protocol error is redirected back to the client
// instead, carrying the client's own state; that redirect never returns to the
// callback, so it gets no cookie.
func gatewayStateOf(location, clientState string) string {
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	state := u.Query().Get("state")
	if state == "" || state == clientState {
		return ""
	}
	return state
}

// requireStateBinding rejects a callback whose state was not issued to this
// browser. The check happens before the pending authorization is looked up,
// so a forged callback never redeems a code.
func requireStateBinding(bound, state string) error {
	if bound == "" {
		return &appoauth.OAuthError{
			Code:        "invalid_request",
			Description: "authorization request was not started in this browser",
		}
	}
	if state == "" || subtle.ConstantTimeCompare([]byte(bound), []byte(state)) != 1 {
		return &appoauth.OAuthError{
			Code:        "invalid_request",
			Description: "state does not match the authorization request started in this browser",
		}
	}
	return nil
}
