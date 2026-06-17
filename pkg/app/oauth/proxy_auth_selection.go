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

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func (p *authProxy) authForResource(ctx context.Context, resource string) (*authdomain.Auth, error) {
	auth, gatewayID, matched := p.resourceAuth(ctx, resource)
	if auth != nil {
		return auth, nil
	}
	// The resource pinned a consumer but it has no OAuth2 identity provider of
	// its own: fall back to the single IdP configured on that consumer's
	// gateway instead of scanning every tenant on the platform.
	if matched {
		a, err := p.singleOAuth2AuthForGateway(ctx, gatewayID)
		if errors.Is(err, ErrAmbiguousAuthorizationServer) {
			return nil, oauthErr("invalid_target",
				"multiple identity providers configured for this gateway; attach a single oauth2 identity provider to the MCP consumer")
		}
		return a, err
	}
	a, err := p.singleOAuth2Auth(ctx)
	if errors.Is(err, ErrAmbiguousAuthorizationServer) {
		return nil, oauthErr("invalid_target",
			"multiple identity providers configured; send an RFC 8707 resource parameter identifying the MCP server")
	}
	return a, err
}

// resourceAuth resolves the RFC 8707 resource indicator to the OAuth2 auth
// attached to the addressed consumer. When the consumer is found but exposes no
// usable OAuth2 auth, it still reports the consumer's gateway so the caller can
// scope the identity-provider fallback to that tenant.
func (p *authProxy) resourceAuth(ctx context.Context, resource string) (*authdomain.Auth, ids.GatewayID, bool) {
	if p.paths == nil || resource == "" {
		return nil, ids.GatewayID{}, false
	}
	u, err := url.Parse(resource)
	if err != nil || u.Path == "" {
		return nil, ids.GatewayID{}, false
	}
	matches, err := p.paths.Match(ctx, u.Host, u.Path)
	if err != nil {
		slog.Warn("oauth: resource lookup failed; falling back to single-issuer selection",
			"resource", resource, "error", err)
		return nil, ids.GatewayID{}, false
	}
	for _, m := range matches {
		for _, a := range m.Auths {
			if a.Enabled && a.Type == authdomain.TypeOAuth2 && a.Config.OAuth2 != nil {
				return a, m.GatewayID, true
			}
		}
	}
	if len(matches) > 0 {
		return nil, matches[0].GatewayID, true
	}
	return nil, ids.GatewayID{}, false
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
		return oauthErr("invalid_request", "redirect_uri must be an https URL or an http loopback URL without a fragment")
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

func pickSingleOAuth2(auths []*authdomain.Auth) (*authdomain.Auth, error) {
	issuers := issuersOf(auths)
	if len(issuers) == 0 {
		return nil, ErrNoAuthorizationServer
	}
	if len(issuers) > 1 {
		return nil, ErrAmbiguousAuthorizationServer
	}
	for _, a := range auths {
		if a.Config.OAuth2 != nil && a.Config.OAuth2.Issuer == issuers[0] {
			return a, nil
		}
	}
	return nil, ErrNoAuthorizationServer
}
