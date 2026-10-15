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
	"net"
	"net/url"
	"strings"
	"unicode"

	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/net/idna"
)

const AuthorizePath = "/oauth/authorize"

const (
	consentDecisionField = "decision"
	consentApprove       = "approve"
)

type gatewayClientFinder interface {
	GetGatewayClient(ctx context.Context, clientID string) (*appoauth.RegisteredGatewayClient, error)
}

type AuthorizeHandler struct {
	proxy    appoauth.AuthProxy
	gateways resolver.GatewayResolver
	clients  gatewayClientFinder
	cookies  FlowCookies
}

func NewAuthorizeHandler(proxy appoauth.AuthProxy, gateways resolver.GatewayResolver, clients gatewayClientFinder, cookies FlowCookies) *AuthorizeHandler {
	return &AuthorizeHandler{proxy: proxy, gateways: gateways, clients: clients, cookies: cookies}
}

func (h *AuthorizeHandler) Handle(c *fiber.Ctx) error {
	req := appoauth.AuthorizeRequest{
		ResponseType:        c.Query("response_type"),
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		State:               c.Query("state"),
		Scope:               c.Query("scope"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
		Resource:            c.Query("resource"),
	}
	ctx := resolver.WithResolvedGateway(c, h.gateways)
	res, err := h.proxy.Authorize(ctx, c.BaseURL(), req)
	if err != nil {
		return writeOAuthError(c, err)
	}
	if res.ConsentState == "" {
		return c.Redirect(res.Location, fiber.StatusFound)
	}
	h.cookies.setConsentCookie(c, res.ConsentState)
	return renderConsentPage(c, consentView{
		ClientName:  h.clientName(ctx, req.ClientID),
		RedirectTo:  redirectTarget(req.RedirectURI),
		RedirectURI: req.RedirectURI,
		State:       res.ConsentState,
	})
}

// Decide completes the consent step for the authorization parked under the
// posted state: approval resumes its IdP redirect, anything else reports the
// refusal to the client.
func (h *AuthorizeHandler) Decide(c *fiber.Ctx) error {
	if site := c.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return writeOAuthError(c, &appoauth.OAuthError{Code: "invalid_request", Description: "consent must be submitted from the consent page"})
	}
	state := c.FormValue("state")
	if !h.cookies.consentCookieMatches(c, state) {
		return writeOAuthError(c, &appoauth.OAuthError{
			Code:        "invalid_request",
			Description: "authorization request was not started in this browser",
		})
	}
	h.cookies.clearConsentCookie(c, state)
	ctx := c.UserContext()
	if c.FormValue(consentDecisionField) != consentApprove {
		location, err := h.proxy.Deny(ctx, state)
		if err != nil {
			return writeOAuthError(c, err)
		}
		if u, perr := url.Parse(location); perr == nil && u.Scheme != "http" && u.Scheme != "https" {
			return renderDeepLinkPage(c, location)
		}
		return c.Redirect(location, fiber.StatusSeeOther)
	}
	location, err := h.proxy.Approve(ctx, state)
	if err != nil {
		return writeOAuthError(c, err)
	}
	// Bind the IdP leg to this browser so the callback can refuse a state (and
	// the code that comes with it) that was minted for someone else.
	h.cookies.setStateCookie(c, state)
	return c.Redirect(location, fiber.StatusSeeOther)
}

func (h *AuthorizeHandler) clientName(ctx context.Context, clientID string) string {
	if h.clients == nil || clientID == "" {
		return ""
	}
	client, err := h.clients.GetGatewayClient(ctx, clientID)
	if err != nil || client == nil {
		return ""
	}
	name := []rune(strings.TrimSpace(strings.Map(dropControl, client.ClientName)))
	if len(name) > maxClientNameRunes {
		name = append(name[:maxClientNameRunes], '…')
	}
	return string(name)
}

// dropControl removes control and format characters, which would let a name
// reorder or hide part of the text around it.
func dropControl(r rune) rune {
	if unicode.In(r, unicode.Cc, unicode.Cf) {
		return -1
	}
	return r
}

const maxClientNameRunes = 48

// redirectTarget names where the authorization code will be delivered: the
// host (in its ASCII form, so a lookalike cannot pass for a known name) for web
// callbacks, the scheme and target for app callbacks.
func redirectTarget(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	switch u.Scheme {
	case "https", "http":
		host, _ := idna.Punycode.ToASCII(u.Hostname())
		if port := u.Port(); port != "" {
			return net.JoinHostPort(host, port)
		}
		return host
	default:
		u.RawQuery, u.Fragment = "", ""
		return u.String()
	}
}
