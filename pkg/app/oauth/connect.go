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
	"sort"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

var _ ConnectService = (*connectService)(nil)

type connectService struct {
	store       ConnectStore
	vault       vaultdomain.Repository
	consumers   appconsumer.DataFinder
	provider    ProviderClient
	registrar   UpstreamRegistrar
	auditor     ConnectAuditor
	sharedOAuth mcpoauth.Provider
	userinfo    UserInfoClient
}

func NewConnectService(
	store ConnectStore,
	vault vaultdomain.Repository,
	consumers appconsumer.DataFinder,
	provider ProviderClient,
	registrar UpstreamRegistrar,
	auditor ConnectAuditor,
	sharedOAuth mcpoauth.Provider,
	userinfo UserInfoClient,
) ConnectService {
	return &connectService{
		store:       store,
		vault:       vault,
		consumers:   consumers,
		provider:    provider,
		registrar:   registrar,
		auditor:     auditor,
		sharedOAuth: sharedOAuth,
		userinfo:    userinfo,
	}
}

func (s *connectService) CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) (string, error) {
	return s.mintTicket(ctx, ConnectTicket{
		GatewayID:    gatewayID.String(),
		PrincipalSub: principalSub,
		ConsumerPath: consumerPath,
	})
}

func (s *connectService) CreateAPIKeyTicket(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub,
	consumerPath string,
	consumerID ids.ConsumerID,
	authID ids.AuthID,
	providers []string,
) (string, error) {
	providerSnapshot := append([]string(nil), providers...)
	ticket := ConnectTicket{
		GatewayID:    gatewayID.String(),
		PrincipalSub: principalSub,
		ConsumerPath: consumerPath,
		ConsumerID:   consumerID.String(),
		AuthID:       authID.String(),
		Providers:    &providerSnapshot,
	}
	id, err := s.mintTicket(ctx, ticket)
	if err != nil {
		return "", err
	}
	identity, ok := connectAuditIdentity(&ticket)
	if ok {
		s.auditor.TicketCreated(ctx, identity)
	}
	return id, nil
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

const credentialExpiryGrace = 60 * time.Second

func (s *connectService) Page(ctx context.Context, ticketID string) (*ConnectPage, error) {
	ticket, gatewayID, data, rc, err := s.resolve(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	providers, err := s.providerStatuses(ctx, gatewayID, ticket, data, rc)
	if err != nil {
		return nil, err
	}
	return &ConnectPage{ConsumerPath: ticket.ConsumerPath, ResumeURL: ticket.ResumeURL, Providers: providers}, nil
}

func (s *connectService) Statuses(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub,
	consumerPath string,
) ([]ProviderStatus, error) {
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	rc, ok := data.MatchPath(consumerPath)
	if !ok {
		return nil, fmt.Errorf("oauth connect: consumer path %s no longer exists", consumerPath)
	}
	ticket := &ConnectTicket{
		GatewayID:    gatewayID.String(),
		PrincipalSub: principalSub,
		ConsumerPath: consumerPath,
	}
	return s.providerStatuses(ctx, gatewayID, ticket, data, rc)
}

func (s *connectService) providerStatuses(
	ctx context.Context,
	gatewayID ids.GatewayID,
	ticket *ConnectTicket,
	data *appconsumer.Data,
	rc *appconsumer.RoutableConsumer,
) ([]ProviderStatus, error) {
	var providers []ProviderStatus
	for _, reg := range data.EffectiveRegistries(rc) {
		cfg := forwardedAuth(reg)
		if cfg == nil {
			continue
		}
		if !connectProviderAllowed(ticket, data, rc, cfg.Provider) {
			continue
		}
		status := ProviderStatus{Provider: cfg.Provider, Registry: reg.Name}
		if reg.MCPTarget != nil {
			status.Code = reg.MCPTarget.Code
		}
		cred, err := s.vault.Find(ctx, gatewayID, ticket.PrincipalSub, cfg.Provider)
		switch {
		case err == nil:
			status.Linked = true
			status.AccountRef = cred.AccountRef
			status.ExpiresAt = cred.ExpiresAt
			status.NeedsReconnect = cred.RefreshToken == "" && cred.Expired(credentialExpiryGrace)
		case errors.Is(err, vaultdomain.ErrUndecryptable):
			status.Linked = true
			status.NeedsReconnect = true
		case !errors.Is(err, vaultdomain.ErrNotFound):
			return nil, fmt.Errorf("oauth connect: check linked credential: %w", err)
		}
		providers = append(providers, status)
	}
	return providers, nil
}

func (s *connectService) Start(ctx context.Context, baseURL, ticketID, provider string) (string, error) {
	ticket, gatewayID, data, rc, err := s.resolve(ctx, ticketID)
	if err != nil {
		return "", err
	}
	if !connectProviderAllowed(ticket, data, rc, provider) {
		return "", ErrProviderNotFound
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
	if !connectProviderAllowed(&st.Ticket, data, rc, provider) {
		return st.TicketID, ErrProviderNotFound
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
		gatewayID, st.Ticket.PrincipalSub, cfg.Provider,
		resolveAccountRef(ctx, s.userinfo, cfg, token),
		token.AccessToken, token.RefreshToken, token.Scopes, token.ExpiresAt,
	)
	if err != nil {
		return st.TicketID, err
	}
	if err := s.vault.Upsert(ctx, cred); err != nil {
		return st.TicketID, err
	}
	if identity, ok := connectAuditIdentity(&st.Ticket); ok {
		s.auditor.ProviderLinked(ctx, identity, cfg.Provider)
	}
	return st.TicketID, nil
}

func (s *connectService) Disconnect(ctx context.Context, ticketID, provider string) error {
	ticket, gatewayID, data, rc, err := s.resolve(ctx, ticketID)
	if err != nil {
		return err
	}
	if !connectProviderAllowed(ticket, data, rc, provider) {
		return ErrProviderNotFound
	}
	if err := s.vault.Delete(ctx, gatewayID, ticket.PrincipalSub, provider); err != nil {
		return err
	}
	if identity, ok := connectAuditIdentity(ticket); ok {
		s.auditor.ProviderUnlinked(ctx, identity, provider)
	}
	return nil
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
	if apiKeyConnectTicket(ticket) &&
		(ticket.Providers == nil ||
			ticket.ConsumerID == "" ||
			ticket.AuthID == "" ||
			!currentAPIKeyIdentity(ticket, rc, gatewayID)) {
		return ids.GatewayID{}, nil, nil, ErrTicketNotFound
	}
	return gatewayID, data, rc, nil
}

func apiKeyConnectTicket(ticket *ConnectTicket) bool {
	return ticket != nil &&
		(ticket.Providers != nil || ticket.ConsumerID != "" || ticket.AuthID != "")
}

func currentAPIKeyIdentity(
	ticket *ConnectTicket,
	rc *appconsumer.RoutableConsumer,
	gatewayID ids.GatewayID,
) bool {
	if ticket == nil || rc == nil || rc.Consumer == nil ||
		rc.Consumer.ID.String() != ticket.ConsumerID {
		return false
	}
	for _, auth := range rc.Auths {
		if auth != nil && auth.ID.String() == ticket.AuthID {
			return validAPIKeyAuth(auth, rc.Consumer, gatewayID)
		}
	}
	return false
}

func connectProviderAllowed(
	ticket *ConnectTicket,
	data *appconsumer.Data,
	rc *appconsumer.RoutableConsumer,
	provider string,
) bool {
	if ticket.Providers == nil {
		return providerRegistry(data.EffectiveRegistries(rc), provider) != nil
	}
	for _, allowed := range *ticket.Providers {
		if allowed == provider {
			return true
		}
	}
	return false
}

func forwardedProviderIDs(registries []*registrydomain.Registry) []string {
	providers := make([]string, 0)
	seen := make(map[string]struct{})
	for _, registry := range registries {
		cfg := forwardedAuth(registry)
		if cfg == nil {
			continue
		}
		if _, ok := seen[cfg.Provider]; ok {
			continue
		}
		seen[cfg.Provider] = struct{}{}
		providers = append(providers, cfg.Provider)
	}
	sort.Strings(providers)
	return providers
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
