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
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func (s *connectService) effectiveAuth(ctx context.Context, baseURL string, gatewayID ids.GatewayID, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil {
		return nil, ErrProviderNotFound
	}
	if cfg.Registration != registrydomain.RegistrationAuto {
		return applySharedOAuth(cfg, reg, s.sharedOAuth), nil
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
		return applySharedOAuth(cfg, reg, s.sharedOAuth), nil
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
		return nil, fmt.Errorf("%w: provider %q", ErrNoRegisteredClient, cfg.Provider)
	}
	return autoAuth(cfg, meta, client), nil
}

func applySharedOAuth(cfg *registrydomain.MCPAuth, reg *registrydomain.Registry, shared mcpoauth.Provider) *registrydomain.MCPAuth {
	if cfg == nil || shared == nil {
		return cfg
	}
	code := ""
	if reg != nil && reg.MCPTarget != nil {
		code = strings.TrimSpace(reg.MCPTarget.Code)
	}
	if code == "" {
		code = strings.TrimSpace(cfg.Provider)
	}
	creds, ok := shared.CredentialsFor(code)
	if !ok {
		return cfg
	}
	if id := strings.TrimSpace(cfg.ClientID); id != "" && id != creds.ClientID {
		return cfg
	}
	out := *cfg
	out.ClientID = creds.ClientID
	out.ClientSecret = creds.ClientSecret
	return &out
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
