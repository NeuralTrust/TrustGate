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
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

var (
	// ErrUpstreamAccountsNotMachine: the consumer is not an application that
	// authenticates with an api key, so it has no account of its own to link.
	// People who sign in link their own (the connect page during a tool call),
	// and an app-identified consumer links per end user through the connections
	// API.
	ErrUpstreamAccountsNotMachine = fmt.Errorf(
		"consumer upstream accounts: only an MCP application that authenticates with an api key holds accounts of its own: %w",
		commonerrors.ErrConflict)
	// ErrUpstreamAccountsAmbiguousKey: the consumer holds several api keys whose
	// names differ, and the upstream account is keyed by that name, so the caller
	// has to say which key it means.
	ErrUpstreamAccountsAmbiguousKey = fmt.Errorf(
		"consumer upstream accounts: this application holds several api keys with different names, which do not share upstream accounts; pass auth_id: %w",
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

// ConsumerUpstreamState is a consumer's whole upstream-credential picture for
// one of its api keys: which servers need an account and where each stands.
type ConsumerUpstreamState struct {
	ConsumerID   ids.ConsumerID
	Slug         string
	AuthID       ids.AuthID
	AuthName     string
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
	State(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, authID ids.AuthID) (*ConsumerUpstreamState, error)
	Link(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, authID ids.AuthID) (*ConsumerConnectLink, error)
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
	authID ids.AuthID,
) (*ConsumerUpstreamState, error) {
	data, rc, auth, err := s.resolve(ctx, gatewayID, consumerID, authID)
	if err != nil {
		return nil, err
	}
	path := appconsumer.MCPPath(rc.Consumer.Slug)
	statuses, err := s.connect.Statuses(ctx, gatewayID, auth.Name, path)
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
		AuthID:       auth.ID,
		AuthName:     auth.Name,
		PrincipalSub: auth.Name,
		Accounts:     accounts,
	}, nil
}

func (s *consumerUpstreamAccounts) Link(
	ctx context.Context,
	gatewayID ids.GatewayID,
	consumerID ids.ConsumerID,
	authID ids.AuthID,
) (*ConsumerConnectLink, error) {
	data, rc, auth, err := s.resolve(ctx, gatewayID, consumerID, authID)
	if err != nil {
		return nil, err
	}
	path := appconsumer.MCPPath(rc.Consumer.Slug)
	providers := forwardedProviderIDs(data.EffectiveRegistries(rc))
	ticket, err := s.connect.CreateAPIKeyTicket(ctx, gatewayID, auth.Name, path, rc.Consumer.ID, auth.ID, providers)
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

// resolve finds the consumer in the gateway and the api key whose name is the
// principal its upstream accounts hang off. A consumer that acts for users has
// none of its own: platform users link their own accounts, and an app-identified
// consumer links per end user through the connections API.
func (s *consumerUpstreamAccounts) resolve(
	ctx context.Context,
	gatewayID ids.GatewayID,
	consumerID ids.ConsumerID,
	authID ids.AuthID,
) (*appconsumer.Data, *appconsumer.RoutableConsumer, *authdomain.Auth, error) {
	if gatewayID.IsNil() || consumerID.IsNil() {
		return nil, nil, nil, fmt.Errorf("gateway id and consumer id are required: %w", commonerrors.ErrValidation)
	}
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("consumer upstream accounts: find consumers: %w", err)
	}
	rc := routableByID(data, consumerID)
	if rc == nil {
		return nil, nil, nil, fmt.Errorf("consumer %s not found: %w", consumerID, commonerrors.ErrNotFound)
	}
	if rc.Consumer.Type != consumerdomain.TypeMCP || rc.Consumer.Identity.ActsForUsers {
		return nil, nil, nil, ErrUpstreamAccountsNotMachine
	}
	auth, err := pickAPIKeyAuth(rc, gatewayID, authID)
	if err != nil {
		return nil, nil, nil, err
	}
	return data, rc, auth, nil
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

// pickAPIKeyAuth resolves which api key's principal to read or link. With an
// explicit id it must be that key; without one, the consumer's keys must agree
// on a name, because the name *is* the principal and keys with different names
// hold different upstream accounts.
func pickAPIKeyAuth(rc *appconsumer.RoutableConsumer, gatewayID ids.GatewayID, authID ids.AuthID) (*authdomain.Auth, error) {
	var chosen *authdomain.Auth
	names := make(map[string]struct{})
	for _, auth := range rc.Auths {
		if !validAPIKeyAuth(auth, rc.Consumer, gatewayID) {
			continue
		}
		if !authID.IsNil() {
			if auth.ID == authID {
				return auth, nil
			}
			continue
		}
		names[strings.TrimSpace(auth.Name)] = struct{}{}
		if chosen == nil {
			chosen = auth
		}
	}
	if !authID.IsNil() {
		return nil, fmt.Errorf("api key %s is not an enabled key of this consumer: %w", authID, commonerrors.ErrNotFound)
	}
	if chosen == nil {
		return nil, ErrUpstreamAccountsNotMachine
	}
	if len(names) > 1 {
		return nil, ErrUpstreamAccountsAmbiguousKey
	}
	return chosen, nil
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
