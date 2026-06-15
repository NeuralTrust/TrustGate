package oauth

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

func (s *connectService) effectiveAuth(ctx context.Context, baseURL string, gatewayID ids.GatewayID, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil {
		return nil, ErrProviderNotFound
	}
	if cfg.Registration != registrydomain.RegistrationAuto {
		return cfg, nil
	}
	meta, err := s.registrar.Discover(ctx, reg.MCPTarget.URL)
	if err != nil {
		return nil, err
	}
	client, err := s.registrar.EnsureClient(ctx, clientKey(gatewayID, reg), meta, connectCallbackURL(baseURL, cfg.Provider))
	if err != nil {
		return nil, err
	}
	return autoAuth(cfg, meta, client), nil
}

func (s *connectService) RefreshAuth(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil {
		return nil, ErrProviderNotFound
	}
	if cfg.Registration != registrydomain.RegistrationAuto {
		return cfg, nil
	}
	meta, err := s.registrar.Discover(ctx, reg.MCPTarget.URL)
	if err != nil {
		return nil, err
	}
	client, err := s.registrar.CachedClient(ctx, clientKey(gatewayID, reg))
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("oauth connect: no registered client for provider %q; consent flow required", cfg.Provider)
	}
	return autoAuth(cfg, meta, client), nil
}

func autoAuth(cfg *registrydomain.MCPAuth, meta *UpstreamAuthServer, client *RegisteredClient) *registrydomain.MCPAuth {
	out := *cfg
	out.ClientID = client.ClientID
	out.ClientSecret = client.ClientSecret
	out.AuthorizeURL = meta.AuthorizationEndpoint
	out.TokenURL = meta.TokenEndpoint
	if len(out.Scopes) == 0 {
		out.Scopes = meta.ScopesSupported
	}
	if out.Resource == "" {
		out.Resource = meta.Resource
	}
	return &out
}

func clientKey(gatewayID ids.GatewayID, reg *registrydomain.Registry) string {
	return gatewayID.String() + "|" + reg.ID.String()
}
