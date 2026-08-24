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
	"fmt"
	"log/slog"
	"net/url"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func (p *authProxy) authForResource(ctx context.Context, resource string) (*authdomain.Auth, error) {
	m := p.resourceAuth(ctx, resource)
	if m.auth != nil {
		return m.auth, nil
	}
	if m.matched {
		if m.validateOnly {
			return nil, oauthErr("invalid_request",
				"the identity provider of this MCP server has no pre-registered client_id, so this gateway cannot broker "+
					"an interactive login: present an access token obtained directly from that identity provider")
		}
		// The consumer authenticates with a credential of its own, so a session
		// brokered here would be refused by the auth chain. Advertising a login
		// would only walk the user through a flow that cannot reach it.
		if m.protected {
			return nil, oauthErr("invalid_target",
				"this MCP server authenticates with a credential of its own: send it on every request "+
					"(an api key travels in the X-AG-API-Key header) instead of signing in here")
		}
		// The resource pinned a consumer but it has no OAuth2 identity provider of
		// its own: fall back to the single IdP configured on that consumer's
		// gateway instead of scanning every tenant on the platform.
		return p.gatewayScopedAuth(ctx, m.gatewayID)
	}
	// No usable resource indicator, but the request was still routed to a
	// specific gateway (by subdomain or by the gateway-slug header). Scope the
	// fallback to that gateway instead of treating every issuer on the platform
	// as a candidate.
	if gw, ok := appgateway.FromContext(ctx); ok {
		return p.gatewayScopedAuth(ctx, gw.ID)
	}
	a, err := p.singleOAuth2Auth(ctx)
	if errors.Is(err, ErrAmbiguousAuthorizationServer) {
		return nil, oauthErr("invalid_target",
			"multiple identity providers configured; send an RFC 8707 resource parameter identifying the MCP server")
	}
	// The platform-wide default has no owning gateway to bind to when the
	// request carries neither a resource indicator nor a routed gateway, so it
	// cannot serve this path; require the caller to identify the MCP server.
	if err == nil && appauth.IsDefaultIdP(a) {
		return nil, oauthErr("invalid_target",
			"send an RFC 8707 resource parameter identifying the MCP server")
	}
	return a, err
}

func (p *authProxy) gatewayScopedAuth(ctx context.Context, gatewayID ids.GatewayID) (*authdomain.Auth, error) {
	a, err := p.singleOAuth2AuthForGateway(ctx, gatewayID)
	switch {
	case errors.Is(err, ErrAmbiguousAuthorizationServer):
		// The gateway hosts several operator-configured IdPs and this MCP consumer
		// pinned none of them. When the built-in NeuralTrust default IdP is
		// configured, fall back to it: this lets a consumer opt into the default
		// simply by not attaching an oauth2 auth of its own, even on a gateway that
		// also serves other identity providers (a consumer that needs a specific
		// one still pins it by attaching that oauth2 auth). Without a default there
		// is no safe way to pick one, so the ambiguity stays a hard error.
		if def := p.brokerCapableDefault(gatewayID); def != nil {
			return def, nil
		}
		return nil, oauthErr("invalid_target",
			"multiple identity providers configured for this gateway; attach a single oauth2 identity provider to the MCP consumer")
	case errors.Is(err, ErrNoAuthorizationServer):
		// The MCP consumer has no identity provider of its own: fall back to the
		// built-in NeuralTrust identity provider when it is configured, bound to
		// this gateway. This is the zero-configuration default that lets an MCP
		// consumer broker interactive logins without the operator standing up
		// their own IdP.
		if def := p.brokerCapableDefault(gatewayID); def != nil {
			return def, nil
		}
		return nil, oauthErr("invalid_request",
			"this MCP server has no oauth2 identity provider; interactive login requires an oauth2 auth with a pre-registered client at your identity provider")
	}
	return a, err
}

// brokerCapableDefault returns the built-in identity provider bound to the
// gateway, or nil when it is unconfigured or cannot broker a login. It gates
// selection and advertisement only; the default stays in the validation
// candidate pool either way.
func (p *authProxy) brokerCapableDefault(gatewayID ids.GatewayID) *authdomain.Auth {
	def := p.credentials.DefaultOAuth2ForGateway(gatewayID)
	if def == nil || !def.CanBrokerLogin() {
		return nil
	}
	return def
}

type resourceMatch struct {
	// auth is the OAuth2 provider attached to the consumer, if any.
	auth *authdomain.Auth
	// gatewayID owns the addressed consumer, so a fallback can be scoped to
	// that tenant rather than the whole platform.
	gatewayID ids.GatewayID
	// matched reports whether the resource addressed a known consumer.
	matched bool
	// protected reports whether the consumer carries an enabled credential of
	// its own, which rules out any identity-provider fallback.
	protected bool
	// validateOnly reports that every identity provider on the consumer can only
	// validate a token the client already holds, so no login can be brokered.
	validateOnly bool
}

// resourceAuth reports the consumer's gateway even when that consumer exposes no
// usable OAuth2 auth, so the caller can scope the identity-provider fallback to
// that tenant rather than the whole platform.
func (p *authProxy) resourceAuth(ctx context.Context, resource string) resourceMatch {
	if p.paths == nil || resource == "" {
		return resourceMatch{}
	}
	u, err := url.Parse(resource)
	if err != nil || u.Path == "" {
		return resourceMatch{}
	}
	matches, err := p.paths.Match(ctx, u.Host, u.Path)
	if err != nil {
		slog.Warn("oauth: resource lookup failed; falling back to single-issuer selection",
			"resource", resource, "error", err)
		return resourceMatch{}
	}
	if len(matches) == 0 {
		return resourceMatch{}
	}
	providers, protected, validateOnly := pathOAuth2Auths(matches)
	out := resourceMatch{
		gatewayID:    matches[0].GatewayID,
		matched:      true,
		protected:    protected,
		validateOnly: len(providers) == 0 && len(validateOnly) > 0,
	}
	if len(providers) > 0 {
		out.auth = providers[0]
	}
	return out
}

func pathOAuth2Auths(matches []appconsumer.PathMatch) (providers []*authdomain.Auth, protected bool, validateOnly []*authdomain.Auth) {
	for _, m := range matches {
		for _, a := range m.Auths {
			if !a.Enabled {
				continue
			}
			protected = true
			if !a.Type.IsIdentityProvider() || a.Config.OAuth2 == nil {
				continue
			}
			if a.CanBrokerLogin() {
				providers = append(providers, a)
				continue
			}
			validateOnly = append(validateOnly, a)
		}
	}
	return providers, protected, validateOnly
}

func (p *authProxy) pendingAuth(ctx context.Context, pending *PendingAuthorization) (*authdomain.Auth, error) {
	if pending.AuthID != "" {
		auths, err := p.credentials.OAuth2Auths(ctx)
		if err != nil {
			return nil, fmt.Errorf("oauth: load oauth2 auths: %w", err)
		}
		for _, a := range auths {
			if a.ID.String() == pending.AuthID {
				return a, nil
			}
		}
		return nil, oauthErr("invalid_request", "the identity provider behind this authorization is no longer configured")
	}
	return p.authForResource(ctx, pending.Resource)
}

func (p *authProxy) validateClientRedirect(ctx context.Context, clientID, redirectURI string) error {
	if clientID != "" && p.store != nil {
		client, err := p.store.GetGatewayClient(ctx, clientID)
		if err != nil {
			return fmt.Errorf("oauth: load client registration: %w", err)
		}
		if client != nil {
			for _, allowed := range client.RedirectURIs {
				if allowed == redirectURI {
					return nil
				}
			}
			return oauthErr("invalid_request", "redirect_uri is not registered for this client")
		}
	}
	if !p.knownClientID(ctx, clientID) {
		return oauthErr("invalid_client", "unknown client_id; register via /oauth/register")
	}
	if !IsAcceptableRedirectURI(redirectURI) {
		return oauthErr("invalid_request", "redirect_uri must be an https URL, an http loopback URL, or a registered private-use URI without a fragment")
	}
	if isPrivateUseRedirectURIString(redirectURI) && !isLegacyPrivateUseRedirectURI(redirectURI) {
		return oauthErr("invalid_request", "private-use redirect_uri must be registered for this client")
	}
	return nil
}

func (p *authProxy) knownClientID(ctx context.Context, clientID string) bool {
	if clientID == "" {
		return true
	}
	auths, err := p.credentials.OAuth2Auths(ctx)
	if err != nil {
		return false
	}
	configured := false
	for _, a := range auths {
		cfg := a.Config.OAuth2
		if cfg == nil || cfg.ClientID == "" {
			continue
		}
		configured = true
		if cfg.ClientID == clientID {
			return true
		}
	}
	return !configured
}

func (p *authProxy) singleOAuth2Auth(ctx context.Context) (*authdomain.Auth, error) {
	auths, err := p.credentials.OAuth2Auths(ctx)
	if err != nil {
		return nil, fmt.Errorf("oauth: load oauth2 auths: %w", err)
	}
	return pickSingleOAuth2(auths)
}

func (p *authProxy) singleOAuth2AuthForGateway(ctx context.Context, gatewayID ids.GatewayID) (*authdomain.Auth, error) {
	auths, err := p.credentials.OAuth2AuthsForGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("oauth: load oauth2 auths for gateway: %w", err)
	}
	return pickSingleOAuth2(auths)
}

// pickSingleOAuth2 treats the built-in NeuralTrust default as a fallback: it
// never causes ambiguity and is only returned when no operator-configured
// provider can broker a login. The default is held to the same brokering
// capability as tenant providers, so a platform IdP configured without a
// client_id stays a validation-only credential instead of being offered as a
// login that cannot complete.
func pickSingleOAuth2(auths []*authdomain.Auth) (*authdomain.Auth, error) {
	real := make([]*authdomain.Auth, 0, len(auths))
	var def *authdomain.Auth
	for _, a := range auths {
		if appauth.IsDefaultIdP(a) {
			if a.CanBrokerLogin() {
				def = a
			}
			continue
		}
		if !a.CanBrokerLogin() {
			continue
		}
		real = append(real, a)
	}
	issuers := issuersOf(real)
	if len(issuers) == 0 {
		if def != nil {
			return def, nil
		}
		return nil, ErrNoAuthorizationServer
	}
	if len(issuers) > 1 {
		return nil, ErrAmbiguousAuthorizationServer
	}
	for _, a := range real {
		if a.Config.OAuth2 != nil && a.Config.OAuth2.Issuer == issuers[0] {
			return a, nil
		}
	}
	return nil, ErrNoAuthorizationServer
}
