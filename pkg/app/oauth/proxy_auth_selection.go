package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

func (p *authProxy) authForResource(ctx context.Context, resource string) (*authdomain.Auth, error) {
	if a := p.resourceAuth(ctx, resource); a != nil {
		return a, nil
	}
	a, err := p.singleOAuth2Auth(ctx)
	if errors.Is(err, ErrAmbiguousAuthorizationServer) {
		return nil, oauthErr("invalid_target",
			"multiple identity providers configured; send an RFC 8707 resource parameter identifying the MCP server")
	}
	return a, err
}

func (p *authProxy) resourceAuth(ctx context.Context, resource string) *authdomain.Auth {
	if p.paths == nil || resource == "" {
		return nil
	}
	u, err := url.Parse(resource)
	if err != nil || u.Path == "" {
		return nil
	}
	matches, err := p.paths.Match(ctx, u.Host, u.Path)
	if err != nil {
		slog.Warn("oauth: resource lookup failed; falling back to single-issuer selection",
			"resource", resource, "error", err)
		return nil
	}
	for _, m := range matches {
		for _, a := range m.Auths {
			if a.Enabled && a.Type == authdomain.TypeOAuth2 && a.Config.OAuth2 != nil {
				return a
			}
		}
	}
	return nil
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
