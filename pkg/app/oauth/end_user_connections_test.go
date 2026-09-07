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
	"testing"
	"time"

	appauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appconsumermocks "github.com/NeuralTrust/TrustGate/pkg/app/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	oauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/oauth/mocks"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

// appUsersConsumerData is an active MCP consumer whose application identifies
// its end users, bound to one forwarded-auth (github) server.
func appUsersConsumerData(gatewayID ids.GatewayID, slug string, authID ids.AuthID, source consumerdomain.IdentitySource) *appconsumer.Data {
	identity := consumerdomain.Identity{}
	if source != "" {
		identity = consumerdomain.Identity{ActsForUsers: true, Source: source}
	}
	return appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gatewayID,
			Type:      consumerdomain.TypeMCP,
			Slug:      slug,
			Active:    true,
			AuthIDs:   []ids.AuthID{authID},
			Identity:  identity,
		},
		Registries: []*registrydomain.Registry{{
			ID:   ids.New[ids.RegistryKind](),
			Name: "GitHub",
			Type: registrydomain.TypeMCP,
			MCPTarget: &registrydomain.MCPTarget{
				Code: "github",
				Auth: &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: "github"},
			},
		}},
	}})
}

func TestEndUserConnections_LinkMintsNamespacedTicket(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appUsersConsumerData(gatewayID, "assistant", authID, consumerdomain.IdentitySourceApp)
	target, _ := data.MatchSlug("assistant")

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(validAPIKeyAuth(gatewayID, authID), nil).Once()
	tickets := oauthmocks.NewConnectService(t)
	tickets.EXPECT().
		CreateTicket(ctx, gatewayID, consumerdomain.EndUserSubject(target.Consumer.ID, "user_123"), appconsumer.MCPPath("assistant")).
		Return("ticket-1", nil).Once()

	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, tickets, oauth.NewNoopConnectAttemptLimiter())
	link, err := svc.Link(ctx, gatewayID, "assistant", "ag_secret", " user_123 ", "github")
	require.NoError(t, err)
	require.Equal(t, "ticket-1", link.Ticket)
	require.Equal(t, "github", link.Provider)
	require.WithinDuration(t, time.Now().Add(oauth.ConnectTicketTTL), link.ExpiresAt, 5*time.Second)
}

func TestEndUserConnections_LinkRejectsUnknownProvider(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appUsersConsumerData(gatewayID, "assistant", authID, consumerdomain.IdentitySourceApp)

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(validAPIKeyAuth(gatewayID, authID), nil).Once()

	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, oauthmocks.NewConnectService(t), nil)
	_, err := svc.Link(ctx, gatewayID, "assistant", "ag_secret", "user_123", "salesforce")
	require.ErrorIs(t, err, oauth.ErrUnknownConnectProvider)
	require.ErrorIs(t, err, commonerrors.ErrValidation)
}

func TestEndUserConnections_RequiresAppIdentifiedUsers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	for name, source := range map[string]consumerdomain.IdentitySource{"acts as the application": "", "users sign in": consumerdomain.IdentitySourcePlatform} {
		t.Run(name, func(t *testing.T) {
			data := appUsersConsumerData(gatewayID, "assistant", authID, source)
			consumers := appconsumermocks.NewDataFinder(t)
			consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
			apiKeys := appauthmocks.NewAPIKeyFinder(t)
			apiKeys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(validAPIKeyAuth(gatewayID, authID), nil).Once()

			svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, oauthmocks.NewConnectService(t), nil)
			_, err := svc.Connections(ctx, gatewayID, "assistant", "ag_secret", "user_123")
			require.ErrorIs(t, err, oauth.ErrEndUserConnectionsUnsupported)
		})
	}
}

func TestEndUserConnections_RejectsForeignKeyAndUnknownSlug(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appUsersConsumerData(gatewayID, "assistant", authID, consumerdomain.IdentitySourceApp)

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Twice()
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	// A key that belongs to another consumer verifies but is not attached here.
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_other").Return(validAPIKeyAuth(gatewayID, ids.New[ids.AuthKind]()), nil).Once()

	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, oauthmocks.NewConnectService(t), nil)
	_, err := svc.Connections(ctx, gatewayID, "assistant", "ag_other", "user_123")
	require.ErrorIs(t, err, oauth.ErrAPIKeyConnectUnauthorized)
	_, err = svc.Connections(ctx, gatewayID, "nope", "ag_secret", "user_123")
	require.ErrorIs(t, err, oauth.ErrAPIKeyConnectUnauthorized, "an unknown slug reads as unauthorized, never as not found")
}

func TestEndUserConnections_ConnectionsReportStates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appUsersConsumerData(gatewayID, "assistant", authID, consumerdomain.IdentitySourceApp)
	target, _ := data.MatchSlug("assistant")

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(validAPIKeyAuth(gatewayID, authID), nil).Once()
	tickets := oauthmocks.NewConnectService(t)
	expires := time.Now().Add(time.Hour).UTC()
	tickets.EXPECT().
		Statuses(ctx, gatewayID, consumerdomain.EndUserSubject(target.Consumer.ID, "user_123"), appconsumer.MCPPath("assistant")).
		Return([]oauth.ProviderStatus{
			{Provider: "github", Registry: "GitHub", Code: "github", Linked: true, AccountRef: "octocat", ExpiresAt: expires},
			{Provider: "linear", Registry: "Linear", Code: "linear", Linked: true, NeedsReconnect: true},
			{Provider: "notion", Registry: "Notion", Code: "notion"},
		}, nil).Once()

	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, tickets, nil)
	got, err := svc.Connections(ctx, gatewayID, "assistant", "ag_secret", "user_123")
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, oauth.ConnectionConnected, got[0].Status)
	require.Equal(t, "octocat", got[0].AccountRef)
	require.Equal(t, expires, got[0].ExpiresAt)
	require.Equal(t, oauth.ConnectionNeedsReconnect, got[1].Status)
	require.Equal(t, oauth.ConnectionNotConnected, got[2].Status)
}

func TestEndUserConnections_InvalidEndUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appUsersConsumerData(gatewayID, "assistant", authID, consumerdomain.IdentitySourceApp)
	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(validAPIKeyAuth(gatewayID, authID), nil).Once()

	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, oauthmocks.NewConnectService(t), nil)
	_, err := svc.Link(ctx, gatewayID, "assistant", "ag_secret", "  ", "")
	require.True(t, errors.Is(err, consumerdomain.ErrInvalidEndUser))
}
