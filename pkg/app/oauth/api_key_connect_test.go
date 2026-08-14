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

package oauth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	appauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appconsumermocks "github.com/NeuralTrust/TrustGate/pkg/app/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	oauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/oauth/mocks"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyConnectService_CreateTicket(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	slug := "runtime"
	rawKey := "ag_secret"
	auth := validAPIKeyAuth(gatewayID, authID)
	data := consumerData(gatewayID, gatewayID, slug, consumerdomain.TypeMCP, true, authID)
	dataFinder := appconsumermocks.NewDataFinder(t)
	apiKeyFinder := appauthmocks.NewAPIKeyFinder(t)
	connectService := oauthmocks.NewConnectService(t)
	limiter := oauthmocks.NewConnectAttemptLimiter(t)
	target, ok := data.MatchSlug(slug)
	require.True(t, ok)

	targetCall := dataFinder.EXPECT().
		FindByGateway(ctx, gatewayID).
		Return(data, nil).
		Once()
	limitCall := limiter.EXPECT().
		Check(ctx, oauth.ConnectAttemptScopeConsumer, target.Consumer.ID.String()).
		Return(nil).
		Once()
	limitCall.NotBefore(targetCall)
	keyCall := apiKeyFinder.EXPECT().
		FindByAPIKey(ctx, rawKey).
		Return(auth, nil).
		Once()
	keyCall.NotBefore(limitCall)
	connectService.EXPECT().
		CreateAPIKeyTicket(
			ctx,
			gatewayID,
			"Exact Principal",
			appconsumer.MCPPath(slug),
			target.Consumer.ID,
			authID,
			[]string{},
		).
		Return("ticket-123", nil).
		Once()

	service := oauth.NewAPIKeyConnectService(apiKeyFinder, dataFinder, connectService, limiter)
	ticket, err := service.CreateTicket(ctx, gatewayID, slug, rawKey)

	require.NoError(t, err)
	require.Equal(t, "ticket-123", ticket)
}

func TestAPIKeyConnectService_CreateTicketSnapshotsProviders(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := consumerData(
		gatewayID,
		gatewayID,
		"runtime",
		consumerdomain.TypeMCP,
		true,
		authID,
	)
	target, ok := data.MatchSlug("runtime")
	require.True(t, ok)
	for index, provider := range []string{"provider-z", "provider-a", "provider-z"} {
		registry, err := registrydomain.NewMCPRegistry(
			gatewayID,
			fmt.Sprintf("registry-%d", index),
			"",
			&registrydomain.MCPTarget{
				URL: "https://upstream.example/mcp",
				Auth: &registrydomain.MCPAuth{
					Mode:         registrydomain.MCPAuthModeForwarded,
					Provider:     provider,
					Registration: registrydomain.RegistrationAuto,
				},
			},
		)
		require.NoError(t, err)
		target.Registries = append(target.Registries, registry)
	}
	auth := validAPIKeyAuth(gatewayID, authID)
	dataFinder := appconsumermocks.NewDataFinder(t)
	apiKeyFinder := appauthmocks.NewAPIKeyFinder(t)
	connectService := oauthmocks.NewConnectService(t)
	dataFinder.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	apiKeyFinder.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(auth, nil).Once()
	connectService.EXPECT().
		CreateAPIKeyTicket(
			ctx,
			gatewayID,
			auth.Name,
			"/runtime/mcp",
			target.Consumer.ID,
			authID,
			[]string{"provider-a", "provider-z"},
		).
		Return("ticket-123", nil).
		Once()

	service := oauth.NewAPIKeyConnectService(
		apiKeyFinder,
		dataFinder,
		connectService,
		oauth.NewNoopConnectAttemptLimiter(),
	)
	ticket, err := service.CreateTicket(ctx, gatewayID, "runtime", "ag_secret")

	require.NoError(t, err)
	require.Equal(t, "ticket-123", ticket)
}

func TestAPIKeyConnectService_ValidateTarget(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	otherGatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	dependencyErr := errors.New("data unavailable")

	tests := []struct {
		name      string
		data      *appconsumer.Data
		finderErr error
		slug      string
		wantErr   error
	}{
		{
			name:    "active MCP consumer",
			data:    consumerData(gatewayID, gatewayID, "runtime", consumerdomain.TypeMCP, true, authID),
			slug:    "runtime",
			wantErr: nil,
		},
		{
			name:    "unknown slug",
			data:    consumerData(gatewayID, gatewayID, "runtime", consumerdomain.TypeMCP, true, authID),
			slug:    "missing",
			wantErr: oauth.ErrAPIKeyConnectUnauthorized,
		},
		{
			name:    "inactive consumer",
			data:    consumerData(gatewayID, gatewayID, "runtime", consumerdomain.TypeMCP, false, authID),
			slug:    "runtime",
			wantErr: oauth.ErrAPIKeyConnectUnauthorized,
		},
		{
			name:    "non MCP consumer",
			data:    consumerData(gatewayID, gatewayID, "runtime", consumerdomain.TypeLLM, true, authID),
			slug:    "runtime",
			wantErr: oauth.ErrAPIKeyConnectUnauthorized,
		},
		{
			name:    "consumer from another gateway",
			data:    consumerData(gatewayID, otherGatewayID, "runtime", consumerdomain.TypeMCP, true, authID),
			slug:    "runtime",
			wantErr: oauth.ErrAPIKeyConnectUnauthorized,
		},
		{
			name:      "data dependency failure",
			finderErr: dependencyErr,
			slug:      "runtime",
			wantErr:   dependencyErr,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			dataFinder := appconsumermocks.NewDataFinder(t)
			dataFinder.EXPECT().
				FindByGateway(ctx, gatewayID).
				Return(tt.data, tt.finderErr).
				Once()

			service := oauth.NewAPIKeyConnectService(
				appauthmocks.NewAPIKeyFinder(t),
				dataFinder,
				oauthmocks.NewConnectService(t),
				oauth.NewNoopConnectAttemptLimiter(),
			)
			err := service.ValidateTarget(ctx, gatewayID, tt.slug)

			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestAPIKeyConnectService_CreateTicketRejectsTargetBeforeKeyLookup(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	ctx := context.Background()
	dataFinder := appconsumermocks.NewDataFinder(t)
	dataFinder.EXPECT().
		FindByGateway(ctx, gatewayID).
		Return(consumerData(
			gatewayID,
			gatewayID,
			"runtime",
			consumerdomain.TypeMCP,
			false,
			authID,
		), nil).
		Once()

	service := oauth.NewAPIKeyConnectService(
		appauthmocks.NewAPIKeyFinder(t),
		dataFinder,
		oauthmocks.NewConnectService(t),
		oauth.NewNoopConnectAttemptLimiter(),
	)
	ticket, err := service.CreateTicket(ctx, gatewayID, "runtime", "ag_secret")

	require.Empty(t, ticket)
	require.ErrorIs(t, err, oauth.ErrAPIKeyConnectUnauthorized)
}

func TestAPIKeyConnectService_CreateTicketConsumerBoundary(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := consumerData(gatewayID, gatewayID, "runtime", consumerdomain.TypeMCP, true, authID)
	target, ok := data.MatchSlug("runtime")
	require.True(t, ok)
	auth := validAPIKeyAuth(gatewayID, authID)
	dataFinder := appconsumermocks.NewDataFinder(t)
	apiKeyFinder := appauthmocks.NewAPIKeyFinder(t)
	connectService := oauthmocks.NewConnectService(t)
	limiter := oauthmocks.NewConnectAttemptLimiter(t)
	attempts := 0

	dataFinder.EXPECT().
		FindByGateway(ctx, gatewayID).
		Return(data, nil).
		Times(101)
	limiter.EXPECT().
		Check(ctx, oauth.ConnectAttemptScopeConsumer, target.Consumer.ID.String()).
		RunAndReturn(func(context.Context, oauth.ConnectAttemptScope, string) error {
			attempts++
			if attempts == 101 {
				return &oauth.ConnectRateLimitExceeded{RetryAfter: time.Minute}
			}
			return nil
		}).
		Times(101)
	apiKeyFinder.EXPECT().
		FindByAPIKey(ctx, "ag_secret").
		Return(auth, nil).
		Times(100)
	connectService.EXPECT().
		CreateAPIKeyTicket(
			ctx,
			gatewayID,
			"Exact Principal",
			"/runtime/mcp",
			target.Consumer.ID,
			authID,
			[]string{},
		).
		Return("ticket-123", nil).
		Times(100)

	service := oauth.NewAPIKeyConnectService(apiKeyFinder, dataFinder, connectService, limiter)
	for attempt := 1; attempt <= 101; attempt++ {
		ticket, err := service.CreateTicket(ctx, gatewayID, "runtime", "ag_secret")
		if attempt <= 100 {
			require.NoError(t, err)
			require.Equal(t, "ticket-123", ticket)
			continue
		}
		require.Empty(t, ticket)
		var exceeded *oauth.ConnectRateLimitExceeded
		require.ErrorAs(t, err, &exceeded)
		require.Equal(t, time.Minute, exceeded.RetryAfter)
	}
}

func TestAPIKeyConnectService_CreateTicketLimiterOutagePrecedesKeyLookup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		cause error
	}{
		{
			name:  "arbitrary backend failure",
			cause: errors.New("redis failed with limiter-detail"),
		},
		{
			name:  "context canceled",
			cause: context.Canceled,
		},
		{
			name:  "deadline exceeded",
			cause: context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			gatewayID := ids.New[ids.GatewayKind]()
			authID := ids.New[ids.AuthKind]()
			data := consumerData(gatewayID, gatewayID, "runtime", consumerdomain.TypeMCP, true, authID)
			target, ok := data.MatchSlug("runtime")
			require.True(t, ok)
			dataFinder := appconsumermocks.NewDataFinder(t)
			limiter := oauthmocks.NewConnectAttemptLimiter(t)
			dataFinder.EXPECT().
				FindByGateway(ctx, gatewayID).
				Return(data, nil).
				Once()
			limiter.EXPECT().
				Check(ctx, oauth.ConnectAttemptScopeConsumer, target.Consumer.ID.String()).
				Return(tt.cause).
				Once()

			service := oauth.NewAPIKeyConnectService(
				appauthmocks.NewAPIKeyFinder(t),
				dataFinder,
				oauthmocks.NewConnectService(t),
				limiter,
			)
			ticket, err := service.CreateTicket(ctx, gatewayID, "runtime", "ag_secret")

			require.Empty(t, ticket)
			require.Equal(
				t,
				"oauth api-key connect: check consumer rate limit: connect rate limit unavailable",
				err.Error(),
			)
			require.ErrorIs(t, err, oauth.ErrConnectRateLimitUnavailable)
			require.ErrorIs(t, err, tt.cause)
			var unavailable *oauth.ConnectRateLimitUnavailable
			require.ErrorAs(t, err, &unavailable)
			require.Equal(t, tt.cause, errors.Unwrap(unavailable))
			require.NotContains(t, err.Error(), "ag_secret")
			require.NotContains(t, err.Error(), target.Consumer.ID.String())
			require.NotContains(t, err.Error(), "limiter-detail")
		})
	}
}

func TestAPIKeyConnectService_CreateTicketRejectsInvalidAuth(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	otherGatewayID := ids.New[ids.GatewayKind]()
	attachedAuthID := ids.New[ids.AuthKind]()

	tests := []struct {
		name      string
		auth      *authdomain.Auth
		finderErr error
	}{
		{
			name:      "unknown key",
			finderErr: authdomain.ErrNotFound,
		},
		{
			name: "nil auth",
		},
		{
			name: "disabled auth",
			auth: &authdomain.Auth{
				ID: attachedAuthID, GatewayID: gatewayID, Name: "principal",
				Type: authdomain.TypeAPIKey, Enabled: false,
			},
		},
		{
			name: "wrong auth type",
			auth: &authdomain.Auth{
				ID: attachedAuthID, GatewayID: gatewayID, Name: "principal",
				Type: authdomain.TypeOAuth2, Enabled: true,
			},
		},
		{
			name: "auth from another gateway",
			auth: &authdomain.Auth{
				ID: attachedAuthID, GatewayID: otherGatewayID, Name: "principal",
				Type: authdomain.TypeAPIKey, Enabled: true,
			},
		},
		{
			name: "auth attached to another consumer",
			auth: &authdomain.Auth{
				ID: ids.New[ids.AuthKind](), GatewayID: gatewayID, Name: "principal",
				Type: authdomain.TypeAPIKey, Enabled: true,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			dataFinder := appconsumermocks.NewDataFinder(t)
			apiKeyFinder := appauthmocks.NewAPIKeyFinder(t)
			dataFinder.EXPECT().
				FindByGateway(ctx, gatewayID).
				Return(consumerData(
					gatewayID,
					gatewayID,
					"runtime",
					consumerdomain.TypeMCP,
					true,
					attachedAuthID,
				), nil).
				Once()
			apiKeyFinder.EXPECT().
				FindByAPIKey(ctx, "ag_secret").
				Return(tt.auth, tt.finderErr).
				Once()

			service := oauth.NewAPIKeyConnectService(
				apiKeyFinder,
				dataFinder,
				oauthmocks.NewConnectService(t),
				oauth.NewNoopConnectAttemptLimiter(),
			)
			ticket, err := service.CreateTicket(ctx, gatewayID, "runtime", "ag_secret")

			require.Empty(t, ticket)
			require.ErrorIs(t, err, oauth.ErrAPIKeyConnectUnauthorized)
			require.NotContains(t, err.Error(), "ag_secret")
		})
	}
}

func TestAPIKeyConnectService_CreateTicketWrapsDependencyErrors(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := consumerData(gatewayID, gatewayID, "runtime", consumerdomain.TypeMCP, true, authID)
	auth := validAPIKeyAuth(gatewayID, authID)
	target, ok := data.MatchSlug("runtime")
	require.True(t, ok)

	tests := []string{"data finder", "API key finder", "connect service"}

	for _, stage := range tests {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			dependencyErr := errors.New("dependency failed")
			dataFinder := appconsumermocks.NewDataFinder(t)
			apiKeyFinder := appauthmocks.NewAPIKeyFinder(t)
			connectService := oauthmocks.NewConnectService(t)
			if stage == "data finder" {
				dataFinder.EXPECT().
					FindByGateway(ctx, gatewayID).
					Return(nil, dependencyErr).
					Once()
			} else {
				dataFinder.EXPECT().
					FindByGateway(ctx, gatewayID).
					Return(data, nil).
					Once()
				if stage == "API key finder" {
					apiKeyFinder.EXPECT().
						FindByAPIKey(ctx, "ag_secret").
						Return(nil, dependencyErr).
						Once()
				} else {
					apiKeyFinder.EXPECT().
						FindByAPIKey(ctx, "ag_secret").
						Return(auth, nil).
						Once()
					connectService.EXPECT().
						CreateAPIKeyTicket(
							ctx,
							gatewayID,
							"Exact Principal",
							"/runtime/mcp",
							target.Consumer.ID,
							authID,
							[]string{},
						).
						Return("", dependencyErr).
						Once()
				}
			}

			service := oauth.NewAPIKeyConnectService(
				apiKeyFinder,
				dataFinder,
				connectService,
				oauth.NewNoopConnectAttemptLimiter(),
			)
			ticket, err := service.CreateTicket(ctx, gatewayID, "runtime", "ag_secret")

			require.Empty(t, ticket)
			require.ErrorIs(t, err, dependencyErr)
			require.NotContains(t, err.Error(), "ag_secret")
		})
	}
}

func validAPIKeyAuth(gatewayID ids.GatewayID, authID ids.AuthID) *authdomain.Auth {
	return &authdomain.Auth{
		ID:        authID,
		GatewayID: gatewayID,
		Name:      "Exact Principal",
		Type:      authdomain.TypeAPIKey,
		Enabled:   true,
	}
}

func consumerData(
	dataGatewayID ids.GatewayID,
	consumerGatewayID ids.GatewayID,
	slug string,
	consumerType consumerdomain.Type,
	active bool,
	authIDs ...ids.AuthID,
) *appconsumer.Data {
	return appconsumer.NewData(dataGatewayID, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: consumerGatewayID,
			Type:      consumerType,
			Slug:      slug,
			Active:    active,
			AuthIDs:   authIDs,
		},
	}})
}
