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

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

var ErrAPIKeyConnectUnauthorized = errors.New("oauth api-key connect: unauthorized")

//go:generate mockery --name=APIKeyConnectService --dir=. --output=./mocks --filename=oauth_api_key_connect_service_mock.go --case=underscore --with-expecter
type APIKeyConnectService interface {
	ValidateTarget(ctx context.Context, gatewayID ids.GatewayID, slug string) error
	CreateTicket(ctx context.Context, gatewayID ids.GatewayID, slug, rawKey string) (string, error)
}

var _ APIKeyConnectService = (*apiKeyConnectService)(nil)

type apiKeyConnectService struct {
	apiKeyFinder   appauth.APIKeyFinder
	dataFinder     appconsumer.DataFinder
	connectService ConnectService
	limiter        ConnectAttemptLimiter
}

func NewAPIKeyConnectService(
	apiKeyFinder appauth.APIKeyFinder,
	dataFinder appconsumer.DataFinder,
	connectService ConnectService,
	limiter ConnectAttemptLimiter,
) APIKeyConnectService {
	return &apiKeyConnectService{
		apiKeyFinder:   apiKeyFinder,
		dataFinder:     dataFinder,
		connectService: connectService,
		limiter:        limiter,
	}
}

func (s *apiKeyConnectService) ValidateTarget(
	ctx context.Context,
	gatewayID ids.GatewayID,
	slug string,
) error {
	_, err := s.findTarget(ctx, gatewayID, slug)
	return err
}

func (s *apiKeyConnectService) CreateTicket(
	ctx context.Context,
	gatewayID ids.GatewayID,
	slug string,
	rawKey string,
) (string, error) {
	target, err := s.findTarget(ctx, gatewayID, slug)
	if err != nil {
		return "", err
	}

	if err := s.limiter.Check(
		ctx,
		ConnectAttemptScopeConsumer,
		target.Consumer.ID.String(),
	); err != nil {
		var exceeded *ConnectRateLimitExceeded
		if !errors.As(err, &exceeded) {
			err = NewConnectRateLimitUnavailable(err)
		}
		return "", fmt.Errorf("oauth api-key connect: check consumer rate limit: %w", err)
	}

	auth, err := s.apiKeyFinder.FindByAPIKey(ctx, rawKey)
	if err != nil {
		if errors.Is(err, authdomain.ErrNotFound) {
			return "", ErrAPIKeyConnectUnauthorized
		}
		return "", fmt.Errorf("oauth api-key connect: find API key: %w", err)
	}
	if !validAPIKeyAuth(auth, target.Consumer, gatewayID) {
		return "", ErrAPIKeyConnectUnauthorized
	}

	ticket, err := s.connectService.CreateTicket(
		ctx,
		gatewayID,
		auth.Name,
		appconsumer.MCPPath(slug),
	)
	if err != nil {
		return "", fmt.Errorf("oauth api-key connect: create ticket: %w", err)
	}
	return ticket, nil
}

func (s *apiKeyConnectService) findTarget(
	ctx context.Context,
	gatewayID ids.GatewayID,
	slug string,
) (*appconsumer.RoutableConsumer, error) {
	data, err := s.dataFinder.FindByGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("oauth api-key connect: find target: %w", err)
	}
	target, ok := data.MatchSlug(slug)
	if !ok || !validMCPConsumer(target, gatewayID) {
		return nil, ErrAPIKeyConnectUnauthorized
	}
	return target, nil
}

func validMCPConsumer(target *appconsumer.RoutableConsumer, gatewayID ids.GatewayID) bool {
	return target != nil &&
		target.Consumer != nil &&
		target.Consumer.Active &&
		target.Consumer.Type == consumerdomain.TypeMCP &&
		target.Consumer.GatewayID == gatewayID
}

func validAPIKeyAuth(auth *authdomain.Auth, consumer *consumerdomain.Consumer, gatewayID ids.GatewayID) bool {
	if auth == nil ||
		!auth.Enabled ||
		auth.Type != authdomain.TypeAPIKey ||
		auth.GatewayID != gatewayID {
		return false
	}
	for _, authID := range consumer.AuthIDs {
		if authID == auth.ID {
			return true
		}
	}
	return false
}
