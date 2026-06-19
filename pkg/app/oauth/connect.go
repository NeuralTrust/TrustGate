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

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/vault"
)

var _ ConnectService = (*connectService)(nil)

type connectService struct {
	store     ConnectStore
	vault     vaultdomain.Repository
	consumers appconsumer.DataFinder
	provider  ProviderClient
	registrar UpstreamRegistrar
}

func NewConnectService(
	store ConnectStore,
	vault vaultdomain.Repository,
	consumers appconsumer.DataFinder,
	provider ProviderClient,
	registrar UpstreamRegistrar,
) ConnectService {
	return &connectService{store: store, vault: vault, consumers: consumers, provider: provider, registrar: registrar}
}

func (s *connectService) CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) (string, error) {
	return s.mintTicket(ctx, ConnectTicket{
		GatewayID:    gatewayID.String(),
		PrincipalSub: principalSub,
		ConsumerPath: consumerPath,
	})
}

func (s *connectService) mintTicket(ctx context.Context, t ConnectTicket) (string, error) {
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := s.store.SaveTicket(ctx, id, t); err != nil {
		return "", err
	}
	return id, nil
}

func (s *connectService) Page(ctx context.Context, ticketID string) (*ConnectPage, error) {
	ticket, gatewayID, data, rc, err := s.resolve(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	page := &ConnectPage{ConsumerPath: ticket.ConsumerPath, ResumeURL: ticket.ResumeURL}
	for _, reg := range data.EffectiveRegistries(rc) {
		cfg := forwardedAuth(reg)
		if cfg == nil {
			continue
		}
		status := ProviderStatus{Provider: cfg.Provider, Registry: reg.Name}
		cred, err := s.vault.Find(ctx, gatewayID, ticket.PrincipalSub, cfg.Provider)
		switch {
		case err == nil:
			status.Linked = true
			status.AccountRef = cred.AccountRef
			status.ExpiresAt = cred.ExpiresAt
		case !errors.Is(err, vaultdomain.ErrNotFound):
			return nil, fmt.Errorf("oauth connect: check linked credential: %w", err)
		}
		page.Providers = append(page.Providers, status)
	}
	return page, nil
}

func (s *connectService) Start(ctx context.Context, baseURL, ticketID, provider string) (string, error) {
	ticket, gatewayID, data, rc, err := s.resolve(ctx, ticketID)
	if err != nil {
		return "", err
	}
	reg := providerRegistry(data.EffectiveRegistries(rc), provider)
	if reg == nil {
		return "", ErrProviderNotFound
	}
	cfg, err := s.effectiveAuth(ctx, baseURL, gatewayID, reg)
	if err != nil {
		return "", err
	}
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := s.store.SaveConnect(ctx, state, ConnectState{
		Ticket:   *ticket,
		TicketID: ticketID,
		Provider: provider,
		Verifier: verifier,
	}); err != nil {
		return "", err
	}
	return s.provider.AuthorizeURL(cfg, connectCallbackURL(baseURL, provider), state, s256(verifier)), nil
}

func (s *connectService) Callback(ctx context.Context, baseURL, provider, state, code, errCode, errDesc string) (string, error) {
	st, err := s.store.TakeConnect(ctx, state)
	if err != nil {
		return "", err
	}
	if st == nil || st.Provider != provider {
		return "", oauthErr("invalid_request", "unknown or expired state")
	}
	if errCode != "" {
		return st.TicketID, oauthErr(errCode, errDesc)
	}
	gatewayID, data, rc, err := s.routable(ctx, &st.Ticket)
	if err != nil {
		return st.TicketID, err
	}
	reg := providerRegistry(data.EffectiveRegistries(rc), provider)
	if reg == nil {
		return st.TicketID, ErrProviderNotFound
	}
	cfg, err := s.effectiveAuth(ctx, baseURL, gatewayID, reg)
	if err != nil {
		return st.TicketID, err
	}
	token, err := s.provider.ExchangeCode(ctx, cfg, code, connectCallbackURL(baseURL, provider), st.Verifier)
	if err != nil {
		return st.TicketID, err
	}
	cred, err := vaultdomain.NewCredential(
		gatewayID, st.Ticket.PrincipalSub, provider, "",
		token.AccessToken, token.RefreshToken, token.Scopes, token.ExpiresAt,
	)
	if err != nil {
		return st.TicketID, err
	}
	if err := s.vault.Upsert(ctx, cred); err != nil {
		return st.TicketID, err
	}
	return st.TicketID, nil
}

func (s *connectService) Disconnect(ctx context.Context, ticketID, provider string) error {
	ticket, gatewayID, _, _, err := s.resolve(ctx, ticketID)
	if err != nil {
		return err
	}
	return s.vault.Delete(ctx, gatewayID, ticket.PrincipalSub, provider)
}

func (s *connectService) resolve(ctx context.Context, ticketID string) (*ConnectTicket, ids.GatewayID, *appconsumer.Data, *appconsumer.RoutableConsumer, error) {
	ticket, err := s.store.GetTicket(ctx, ticketID)
	if err != nil {
		return nil, ids.GatewayID{}, nil, nil, err
	}
	if ticket == nil {
		return nil, ids.GatewayID{}, nil, nil, ErrTicketNotFound
	}
	gatewayID, data, rc, err := s.routable(ctx, ticket)
	if err != nil {
		return nil, ids.GatewayID{}, nil, nil, err
	}
	return ticket, gatewayID, data, rc, nil
}

func (s *connectService) routable(ctx context.Context, ticket *ConnectTicket) (ids.GatewayID, *appconsumer.Data, *appconsumer.RoutableConsumer, error) {
	gatewayID, err := ids.Parse[ids.GatewayKind](ticket.GatewayID)
	if err != nil {
		return ids.GatewayID{}, nil, nil, fmt.Errorf("oauth connect: bad gateway id in ticket: %w", err)
	}
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return ids.GatewayID{}, nil, nil, err
	}
	rc, ok := data.MatchPath(ticket.ConsumerPath)
	if !ok {
		return ids.GatewayID{}, nil, nil, fmt.Errorf("oauth connect: consumer path %s no longer exists", ticket.ConsumerPath)
	}
	return gatewayID, data, rc, nil
}

func forwardedAuth(reg *registrydomain.Registry) *registrydomain.MCPAuth {
	if reg == nil || !reg.IsMCP() || reg.MCPTarget == nil || reg.MCPTarget.Auth == nil {
		return nil
	}
	if reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeForwarded {
		return nil
	}
	return reg.MCPTarget.Auth
}

func providerRegistry(regs []*registrydomain.Registry, provider string) *registrydomain.Registry {
	for _, reg := range regs {
		if cfg := forwardedAuth(reg); cfg != nil && cfg.Provider == provider {
			return reg
		}
	}
	return nil
}

func connectCallbackURL(baseURL, provider string) string {
	return baseURL + "/oauth/callback/" + provider
}
