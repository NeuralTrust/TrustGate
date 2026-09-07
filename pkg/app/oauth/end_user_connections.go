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
)

// ConnectTicketTTL is how long a connect ticket (and so a connect link handed
// to an end user) stays redeemable.
const ConnectTicketTTL = 15 * time.Minute

var (
	// ErrEndUserConnectionsUnsupported: the consumer does not identify its end
	// users (identity.source is not app), so there are no per-user connections
	// to link through the application.
	ErrEndUserConnectionsUnsupported = fmt.Errorf("oauth end-user connections: consumer does not identify its end users: %w", commonerrors.ErrConflict)
	// ErrUnknownConnectProvider: the requested provider is not a forwarded-auth
	// server of the consumer.
	ErrUnknownConnectProvider = fmt.Errorf("oauth end-user connections: unknown provider: %w", commonerrors.ErrValidation)
)

// Connection states reported to the application, the equivalent of Composio's
// wait_for_connection outcome.
const (
	ConnectionConnected      = "connected"
	ConnectionNeedsReconnect = "needs_reconnect"
	ConnectionNotConnected   = "not_connected"
)

// EndUserLink is a connect link minted for one end user of an application.
type EndUserLink struct {
	Ticket    string
	Provider  string
	ExpiresAt time.Time
}

// EndUserConnection is the state of one upstream connection of an end user.
type EndUserConnection struct {
	Provider   string
	Registry   string
	Code       string
	Status     string
	AccountRef string
	ExpiresAt  time.Time
}

// EndUserConnectionsService lets an application that identifies its own end
// users (identity.source = app) drive their upstream connections proactively:
// mint a connect link to hand to a user before their first tool call, and read
// which of the consumer's servers that user has connected. Both are
// authenticated with the consumer's API key.
//
//go:generate mockery --name=EndUserConnectionsService --dir=. --output=./mocks --filename=oauth_end_user_connections_service_mock.go --case=underscore --with-expecter
type EndUserConnectionsService interface {
	Link(ctx context.Context, gatewayID ids.GatewayID, slug, rawKey, endUser, provider string) (*EndUserLink, error)
	Connections(ctx context.Context, gatewayID ids.GatewayID, slug, rawKey, endUser string) ([]EndUserConnection, error)
}

// endUserAPIKeys is the API-key lookup the service needs.
type endUserAPIKeys interface {
	FindByAPIKey(ctx context.Context, rawKey string) (*authdomain.Auth, error)
}

// endUserConsumers is the consumer lookup the service needs.
type endUserConsumers interface {
	FindByGateway(ctx context.Context, gatewayID ids.GatewayID) (*appconsumer.Data, error)
}

// endUserTickets is the slice of the connect service the end-user flow uses.
type endUserTickets interface {
	CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) (string, error)
	Statuses(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) ([]ProviderStatus, error)
}

var _ EndUserConnectionsService = (*endUserConnectionsService)(nil)

type endUserConnectionsService struct {
	apiKeys   endUserAPIKeys
	consumers endUserConsumers
	tickets   endUserTickets
	limiter   ConnectAttemptLimiter
	now       func() time.Time
}

// NewEndUserConnectionsService wires the end-user connections flow over the
// API-key lookup, the consumer data and the connect service.
func NewEndUserConnectionsService(
	apiKeys endUserAPIKeys,
	consumers endUserConsumers,
	tickets endUserTickets,
	limiter ConnectAttemptLimiter,
) EndUserConnectionsService {
	if limiter == nil {
		limiter = NewNoopConnectAttemptLimiter()
	}
	return &endUserConnectionsService{
		apiKeys:   apiKeys,
		consumers: consumers,
		tickets:   tickets,
		limiter:   limiter,
		now:       time.Now,
	}
}

func (s *endUserConnectionsService) Link(
	ctx context.Context,
	gatewayID ids.GatewayID,
	slug, rawKey, endUser, provider string,
) (*EndUserLink, error) {
	data, target, err := s.authenticate(ctx, gatewayID, slug, rawKey)
	if err != nil {
		return nil, err
	}
	if err := consumerdomain.ValidateEndUser(endUser); err != nil {
		return nil, err
	}
	provider = strings.TrimSpace(provider)
	if provider != "" && !containsProvider(forwardedProviderIDs(data.EffectiveRegistries(target)), provider) {
		return nil, fmt.Errorf("%w: %q is not a connectable server of this consumer", ErrUnknownConnectProvider, provider)
	}
	if err := s.limiter.Check(ctx, ConnectAttemptScopeConsumer, target.Consumer.ID.String()); err != nil {
		var exceeded *ConnectRateLimitExceeded
		if !errors.As(err, &exceeded) {
			err = NewConnectRateLimitUnavailable(err)
		}
		return nil, fmt.Errorf("oauth end-user connections: check consumer rate limit: %w", err)
	}
	ticket, err := s.tickets.CreateTicket(ctx, gatewayID,
		consumerdomain.EndUserSubject(target.Consumer.ID, endUser), appconsumer.MCPPath(slug))
	if err != nil {
		return nil, fmt.Errorf("oauth end-user connections: create ticket: %w", err)
	}
	return &EndUserLink{Ticket: ticket, Provider: provider, ExpiresAt: s.now().UTC().Add(ConnectTicketTTL)}, nil
}

func (s *endUserConnectionsService) Connections(
	ctx context.Context,
	gatewayID ids.GatewayID,
	slug, rawKey, endUser string,
) ([]EndUserConnection, error) {
	_, target, err := s.authenticate(ctx, gatewayID, slug, rawKey)
	if err != nil {
		return nil, err
	}
	if err := consumerdomain.ValidateEndUser(endUser); err != nil {
		return nil, err
	}
	statuses, err := s.tickets.Statuses(ctx, gatewayID,
		consumerdomain.EndUserSubject(target.Consumer.ID, endUser), appconsumer.MCPPath(slug))
	if err != nil {
		return nil, fmt.Errorf("oauth end-user connections: read statuses: %w", err)
	}
	out := make([]EndUserConnection, 0, len(statuses))
	for _, st := range statuses {
		out = append(out, EndUserConnection{
			Provider:   st.Provider,
			Registry:   st.Registry,
			Code:       st.Code,
			Status:     connectionStatus(st),
			AccountRef: st.AccountRef,
			ExpiresAt:  st.ExpiresAt,
		})
	}
	return out, nil
}

// authenticate resolves the consumer behind the slug and checks the API key
// belongs to it. An unknown or non-MCP slug and a wrong key both read as
// unauthorized so the endpoint never confirms which consumers exist; a consumer
// that does not identify its end users is reported as such, since the caller
// already proved it holds its key.
func (s *endUserConnectionsService) authenticate(
	ctx context.Context,
	gatewayID ids.GatewayID,
	slug, rawKey string,
) (*appconsumer.Data, *appconsumer.RoutableConsumer, error) {
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth end-user connections: find consumer: %w", err)
	}
	target, ok := data.MatchSlug(slug)
	if !ok || !validMCPConsumer(target, gatewayID) {
		return nil, nil, ErrAPIKeyConnectUnauthorized
	}
	auth, err := s.apiKeys.FindByAPIKey(ctx, strings.TrimSpace(rawKey))
	if err != nil {
		if errors.Is(err, authdomain.ErrNotFound) {
			return nil, nil, ErrAPIKeyConnectUnauthorized
		}
		return nil, nil, fmt.Errorf("oauth end-user connections: find API key: %w", err)
	}
	if !validAPIKeyAuth(auth, target.Consumer, gatewayID) {
		return nil, nil, ErrAPIKeyConnectUnauthorized
	}
	if !target.Consumer.Identity.AppUsers() {
		return nil, nil, ErrEndUserConnectionsUnsupported
	}
	return data, target, nil
}

func connectionStatus(st ProviderStatus) string {
	switch {
	case st.Linked && st.NeedsReconnect:
		return ConnectionNeedsReconnect
	case st.Linked:
		return ConnectionConnected
	default:
		return ConnectionNotConnected
	}
}

func containsProvider(providers []string, want string) bool {
	for _, p := range providers {
		if p == want {
			return true
		}
	}
	return false
}
