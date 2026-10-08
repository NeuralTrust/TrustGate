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

func (f FlowCookies) stateCookieName(c *fiber.Ctx) string {
	if f.secure(c) {
		return stateCookieSecureName
	}
	return stateCookiePlainName
}

// setStateCookie remembers the gateway state of the IdP leg in the browser.
func (f FlowCookies) setStateCookie(c *fiber.Ctx, state string) {
	c.Cookie(&fiber.Cookie{
		Name:     f.stateCookieName(c),
		Value:    state,
		Path:     "/",
		MaxAge:   int(stateCookieMaxAge / time.Second),
		Secure:   f.secure(c),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// clearStateCookie expires the binding once the callback has consumed it. The
// attributes must mirror setStateCookie or a browser will not match the
// __Host- cookie it is meant to delete.
func (f FlowCookies) clearStateCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     f.stateCookieName(c),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   f.secure(c),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
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

const (
	consentCookieSecureName = "__Host-oauth_consent_"
	consentCookiePlainName  = "oauth_consent_"
	consentCookieMaxAge     = 5 * time.Minute
)

// consentCookieName is per flow, so consent pages open side by side do not
// displace each other.
func (f FlowCookies) consentCookieName(c *fiber.Ctx, state string) string {
	sum := sha256.Sum256([]byte(state))
	suffix := hex.EncodeToString(sum[:8])
	if f.secure(c) {
		return consentCookieSecureName + suffix
	}
	return consentCookiePlainName + suffix
}

// setConsentCookie marks the browser that was shown the consent page for
// state. SameSite Lax keeps it off form posts from other sites.
func (f FlowCookies) setConsentCookie(c *fiber.Ctx, state string) {
	c.Cookie(&fiber.Cookie{
		Name:     f.consentCookieName(c, state),
		Value:    state,
		Path:     "/",
		MaxAge:   int(consentCookieMaxAge / time.Second),
		Secure:   f.secure(c),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

func (f FlowCookies) clearConsentCookie(c *fiber.Ctx, state string) {
	c.Cookie(&fiber.Cookie{
		Name:     f.consentCookieName(c, state),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   f.secure(c),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

func (f FlowCookies) consentCookieMatches(c *fiber.Ctx, state string) bool {
	if state == "" {
		return false
	}
	bound := c.Cookies(f.consentCookieName(c, state))
	return bound != "" && subtle.ConstantTimeCompare([]byte(bound), []byte(state)) == 1
}

// FlowCookies sets the cookies that tie an authorization flow to one browser.
type FlowCookies struct {
	// AllowInsecure lets a plain-http request on a host other than loopback use
	// cookies without the Secure attribute (local DNS, on-prem over http).
	AllowInsecure bool
}

// secure reports whether the flow cookies take the Secure, __Host- form.
// Loopback hosts are always allowed plain http; any other host needs
// AllowInsecure for that.
func (f FlowCookies) secure(c *fiber.Ctx) bool {
	if c.Secure() {
		return true
	}
	if f.AllowInsecure {
		return false
	}
	host := c.Hostname()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}
