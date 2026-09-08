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
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

var (
	// ErrUpstreamAccountsNotMachine: the consumer does not act as the application
	// itself, so it has no account of its own to link. People who sign in link
	// their own (the connect page during a tool call), and an app-identified
	// consumer links per end user through the connections API.
	ErrUpstreamAccountsNotMachine = fmt.Errorf(
		"consumer upstream accounts: only an MCP consumer that acts as the application itself holds accounts of its own: %w",
		commonerrors.ErrConflict)
	// ErrUpstreamAccountNotForwarded: the registry is bound to the consumer but
	// carries its own credential (or needs none, or wants the caller's token), so
	// there is no account of the application's to link on it.
	ErrUpstreamAccountNotForwarded = fmt.Errorf(
		"consumer upstream accounts: this server does not forward a stored credential, so it has no account to authorize: %w",
		commonerrors.ErrConflict)
)

// UpstreamAccount is one MCP server bound to a consumer and what that server
// wants from the application: nothing, when it carries a credential of its own
// (`static`, `client_credentials`) or needs none; or one linked account, when it
// forwards a stored credential — and then whether the application has linked one.
type UpstreamAccount struct {
	RegistryID ids.RegistryID
	Registry   string
	Code       string
	// Mode is the upstream auth mode verbatim, so the caller can explain the
	// server without re-deriving the taxonomy.
	Mode               registrydomain.MCPAuthMode
	NeedsLinkedAccount bool
	Provider           string
	Linked             bool
	AccountRef         string
	Scopes             []string
	ExpiresAt          time.Time
	NeedsReconnect     bool
}

// ConsumerUpstreamState is an application's whole upstream-credential picture:
// which of its servers need an account of its own and where each one stands.
// It names no credential, because the accounts hang off the consumer — every
// api key and certificate the application holds reaches the same accounts.
type ConsumerUpstreamState struct {
	ConsumerID   ids.ConsumerID
	Slug         string
	PrincipalSub string
	Accounts     []UpstreamAccount
}

// NeedsLinking reports whether any bound server is still waiting for the
// application's account.
func (s *ConsumerUpstreamState) NeedsLinking() bool {
	for _, a := range s.Accounts {
		if a.NeedsLinkedAccount && (!a.Linked || a.NeedsReconnect) {
			return true
		}
	}
	return false
}

// ConsumerConnectLink is a connect link an admin can walk to link the
// application's upstream accounts, without holding the api key itself.
type ConsumerConnectLink struct {
	Ticket       string
	ConsumerPath string
	Providers    []string
	ExpiresAt    time.Time
}

// ConsumerUpstreamAccounts serves the admin side of "connect this application's
// upstream accounts": what each bound MCP server needs, and a link to link it.
// It exists because the alternative — the self-service page at /{slug}/connect —
// requires whoever links the accounts to hold the consumer's api key, which an
// admin in the console does not have (only its hash is stored).
//
//go:generate mockery --name=ConsumerUpstreamAccounts --dir=. --output=./mocks --filename=oauth_consumer_upstream_accounts_mock.go --case=underscore --with-expecter
type ConsumerUpstreamAccounts interface {
	State(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID) (*ConsumerUpstreamState, error)
	// Link mints the connect ticket. A nil registryID covers every server of the
	// application that forwards a credential; naming one narrows the ticket to
	// that server alone, which is how a row authorizes just itself.
	Link(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, registryID ids.RegistryID) (*ConsumerConnectLink, error)
}

var _ ConsumerUpstreamAccounts = (*consumerUpstreamAccounts)(nil)

type consumerUpstreamAccounts struct {
	consumers appconsumer.DataFinder
	connect   ConnectService
}

func NewConsumerUpstreamAccounts(consumers appconsumer.DataFinder, connect ConnectService) (ConsumerUpstreamAccounts, error) {
	if consumers == nil || connect == nil {
		return nil, errors.New("consumer upstream accounts: consumers and connect service are required")
	}
	return &consumerUpstreamAccounts{consumers: consumers, connect: connect}, nil
}

func (s *consumerUpstreamAccounts) State(
	ctx context.Context,
	gatewayID ids.GatewayID,
	consumerID ids.ConsumerID,
) (*ConsumerUpstreamState, error) {
	data, rc, err := s.resolve(ctx, gatewayID, consumerID)
	if err != nil {
		return nil, err
	}
	path := appconsumer.MCPPath(rc.Consumer.Slug)
	principalSub := consumerdomain.AppSubject(rc.Consumer.ID)
	statuses, err := s.connect.Statuses(ctx, gatewayID, principalSub, path)
	if err != nil {
		return nil, err
	}
	byProvider := make(map[string]ProviderStatus, len(statuses))
	for _, st := range statuses {
		byProvider[st.Provider] = st
	}

	registries := data.EffectiveRegistries(rc)
	accounts := make([]UpstreamAccount, 0, len(registries))
	for _, reg := range registries {
		if reg == nil || !reg.IsMCP() || reg.MCPTarget == nil {
			continue
		}
		account := UpstreamAccount{
			RegistryID: reg.ID,
			Registry:   reg.Name,
			Code:       reg.MCPTarget.Code,
			Mode:       upstreamMode(reg),
		}
		if cfg := forwardedAuth(reg); cfg != nil {
			account.NeedsLinkedAccount = true
			account.Provider = cfg.Provider
			if st, ok := byProvider[cfg.Provider]; ok {
				account.Linked = st.Linked
				account.AccountRef = st.AccountRef
				account.Scopes = st.Scopes
				account.ExpiresAt = st.ExpiresAt
				account.NeedsReconnect = st.NeedsReconnect
			}
		}
		accounts = append(accounts, account)
	}
	return &ConsumerUpstreamState{
		ConsumerID:   rc.Consumer.ID,
		Slug:         rc.Consumer.Slug,
		PrincipalSub: principalSub,
		Accounts:     accounts,
	}, nil
}

func (s *consumerUpstreamAccounts) Link(
	ctx context.Context,
	gatewayID ids.GatewayID,
	consumerID ids.ConsumerID,
	registryID ids.RegistryID,
) (*ConsumerConnectLink, error) {
	data, rc, err := s.resolve(ctx, gatewayID, consumerID)
	if err != nil {
		return nil, err
	}
	path := appconsumer.MCPPath(rc.Consumer.Slug)
	registries := data.EffectiveRegistries(rc)
	if !registryID.IsNil() {
		registries, err = onlyRegistry(registries, registryID)
		if err != nil {
			return nil, err
		}
	}
	providers := forwardedProviderIDs(registries)
	// No auth id: the admin holds no api key of this application, and the link
	// does not need one — the accounts are the consumer's.
	ticket, err := s.connect.CreateAppTicket(
		ctx, gatewayID, consumerdomain.AppSubject(rc.Consumer.ID), path, rc.Consumer.ID, ids.AuthID{}, providers)
	if err != nil {
		return nil, err
	}
	return &ConsumerConnectLink{
		Ticket:       ticket,
		ConsumerPath: path,
		Providers:    providers,
		ExpiresAt:    time.Now().UTC().Add(ConnectTicketTTL),
	}, nil
}

// resolve finds the machine MCP consumer these accounts belong to. A consumer
// that acts for users has no account of its own: platform users link their own
// on the connect page, and an app-identified consumer links one per end user
// through the connections API. No credential is looked up — the accounts hang
// off the consumer, so an application that authenticates with a client
// certificate and holds no api key at all still has accounts to link.
func (s *consumerUpstreamAccounts) resolve(
	ctx context.Context,
	gatewayID ids.GatewayID,
	consumerID ids.ConsumerID,
) (*appconsumer.Data, *appconsumer.RoutableConsumer, error) {
	if gatewayID.IsNil() || consumerID.IsNil() {
		return nil, nil, fmt.Errorf("gateway id and consumer id are required: %w", commonerrors.ErrValidation)
	}
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return nil, nil, fmt.Errorf("consumer upstream accounts: find consumers: %w", err)
	}
	rc := routableByID(data, consumerID)
	if rc == nil {
		return nil, nil, fmt.Errorf("consumer %s not found: %w", consumerID, commonerrors.ErrNotFound)
	}
	if rc.Consumer.Type != consumerdomain.TypeMCP || rc.Consumer.Identity.ActsForUsers {
		return nil, nil, ErrUpstreamAccountsNotMachine
	}
	return data, rc, nil
}

// onlyRegistry narrows the application's servers to the one named, so the
// ticket it mints covers that server alone. A registry the consumer is not
// bound to is not found; one that carries its own credential has nothing to
// authorize, which is a conflict rather than an empty ticket — an empty
// provider snapshot would mint a link whose page offers nothing.
//
// Two bound servers may still share one provider, and then a ticket for either
// covers both: the account is keyed by provider, so that is what "the same
// account" means, not a leak.
func onlyRegistry(
	registries []*registrydomain.Registry,
	registryID ids.RegistryID,
) ([]*registrydomain.Registry, error) {
	for _, reg := range registries {
		if reg == nil || reg.ID != registryID {
			continue
		}
		if forwardedAuth(reg) == nil {
			return nil, ErrUpstreamAccountNotForwarded
		}
		return []*registrydomain.Registry{reg}, nil
	}
	return nil, fmt.Errorf("registry %s is not bound to this consumer: %w", registryID, commonerrors.ErrNotFound)
}

func routableByID(data *appconsumer.Data, consumerID ids.ConsumerID) *appconsumer.RoutableConsumer {
	if data == nil {
		return nil
	}
	for i := range data.Consumers {
		rc := &data.Consumers[i]
		if rc.Consumer != nil && rc.Consumer.ID == consumerID {
			return rc
		}
	}
	return nil
}

func upstreamMode(reg *registrydomain.Registry) registrydomain.MCPAuthMode {
	if reg == nil || reg.MCPTarget == nil || reg.MCPTarget.Auth == nil {
		return registrydomain.MCPAuthModeNone
	}
	if mode := reg.MCPTarget.Auth.Mode; mode != "" {
		return mode
	}
	return registrydomain.MCPAuthModeNone
}
