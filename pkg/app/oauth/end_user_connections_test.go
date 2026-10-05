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
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

// appUsersConsumerData is an active MCP consumer bound to one forwarded-auth
// (github) server. Every MCP consumer serves both actors now, so there is
// nothing to vary.
func appUsersConsumerData(gatewayID ids.GatewayID, slug string, authID ids.AuthID) *appconsumer.Data {
	identity := consumerdomain.Identity{}
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
	data := appUsersConsumerData(gatewayID, "assistant", authID)
	target, _ := data.MatchSlug("assistant")

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(validAPIKeyAuth(gatewayID, authID), nil).Once()
	tickets := oauthmocks.NewConnectService(t)
	// Pinned to the provider the link names: the ticket, not the URL, is what
	// decides what its holder may connect, revoke and see.
	tickets.EXPECT().
		CreateProviderTicket(ctx, gatewayID, consumerdomain.EndUserSubject(target.Consumer.ID, "user_123"), appconsumer.MCPPath("assistant"), "github").
		Return("ticket-1", nil).Once()

	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, tickets, oauth.NewNoopConnectAttemptLimiter())
	link, err := svc.Link(ctx, gatewayID, "assistant", "ag_secret", " user_123 ", "github", "")
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
	data := appUsersConsumerData(gatewayID, "assistant", authID)

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(validAPIKeyAuth(gatewayID, authID), nil).Once()

	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, oauthmocks.NewConnectService(t), nil)
	_, err := svc.Link(ctx, gatewayID, "assistant", "ag_secret", "user_123", "salesforce", "")
	require.ErrorIs(t, err, oauth.ErrUnknownConnectProvider)
	require.ErrorIs(t, err, commonerrors.ErrValidation)
}

// Both actors exist on every MCP consumer now — the application itself, and
// whoever it names on a request — so asking about one no longer means the
// other is unavailable, and neither form is refused for what the consumer is.
func TestEndUserConnections_RejectsForeignKeyAndUnknownSlug(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appUsersConsumerData(gatewayID, "assistant", authID)

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
	data := appUsersConsumerData(gatewayID, "assistant", authID)
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
			{Provider: "notion", Registry: "Notion", Code: "notion", Instance: "reg-notion"},
			{Provider: "linear", Registry: "Linear (team)", Code: "linear", Instance: "reg-linear-team", Shared: true},
		}, nil).Once()

	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, tickets, nil)
	got, err := svc.Connections(ctx, gatewayID, "assistant", "ag_secret", "user_123")
	require.NoError(t, err)
	require.Len(t, got, 4)
	require.Equal(t, "reg-notion", got[2].Instance)
	require.False(t, got[2].Shared)
	// A shared account nobody connected reads not_connected like the user's own,
	// and only this says a connect link would not fix it.
	require.Equal(t, oauth.ConnectionNotConnected, got[3].Status)
	require.True(t, got[3].Shared)
	require.Equal(t, "reg-linear-team", got[3].Instance)
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
	data := appUsersConsumerData(gatewayID, "assistant", authID)
	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(validAPIKeyAuth(gatewayID, authID), nil).Once()

	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, oauthmocks.NewConnectService(t), nil)
	_, err := svc.Link(ctx, gatewayID, "assistant", "ag_secret", "  ", "", "")
	require.True(t, errors.Is(err, consumerdomain.ErrInvalidEndUser))
}

// The preflight a batch runs before it starts. Nobody is present to follow a
// connect link once it is running, so the run either knows its own accounts
// are good beforehand or finds out on the call that fails.
func TestAppConnections_ReportTheApplicationsOwnAccounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appUsersConsumerData(gatewayID, "nightly-jobs", authID)
	target, _ := data.MatchSlug("nightly-jobs")

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(validAPIKeyAuth(gatewayID, authID), nil).Once()
	tickets := oauthmocks.NewConnectService(t)
	expires := time.Now().Add(time.Hour).UTC()
	tickets.EXPECT().
		Statuses(ctx, gatewayID, consumerdomain.AppSubject(target.Consumer.ID), appconsumer.MCPPath("nightly-jobs")).
		Return([]oauth.ProviderStatus{
			{Provider: "github", Registry: "GitHub", Code: "github", Linked: true, AccountRef: "ops@corp.com", ExpiresAt: expires},
			{Provider: "notion", Registry: "Notion", Code: "notion"},
		}, nil).Once()

	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, tickets, nil)
	got, err := svc.AppConnections(ctx, gatewayID, "nightly-jobs", "ag_secret")
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, oauth.ConnectionConnected, got[0].Status)
	require.Equal(t, "ops@corp.com", got[0].AccountRef,
		"the account is the application's own, not a user's")
	// The expiry is what lets a run be fixed before it starts rather than
	// after it fails halfway.
	require.Equal(t, expires, got[0].ExpiresAt)
	require.Equal(t, oauth.ConnectionNotConnected, got[1].Status)
}

// A consumer no longer declares who it acts for, so the application actor is
// available on every MCP consumer and nothing is refused for its shape.

// A key that belongs to another consumer must not read another application's
// accounts, and an unknown slug must not confirm which consumers exist.
func TestAppConnections_RejectAForeignKeyAndAnUnknownSlug(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appUsersConsumerData(gatewayID, "nightly-jobs", authID)

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Twice()
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_other").
		Return(validAPIKeyAuth(gatewayID, ids.New[ids.AuthKind]()), nil).Once()
	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, oauthmocks.NewConnectService(t), nil)

	_, err := svc.AppConnections(ctx, gatewayID, "nightly-jobs", "ag_other")
	require.ErrorIs(t, err, oauth.ErrAPIKeyConnectUnauthorized)

	_, err = svc.AppConnections(ctx, gatewayID, "does-not-exist", "ag_secret")
	require.ErrorIs(t, err, oauth.ErrAPIKeyConnectUnauthorized)
}

// validAPIKeyAuth is an enabled api key of this gateway, as the finder returns
// it. It lived beside the api-key connect page until that page was deleted.
func validAPIKeyAuth(gatewayID ids.GatewayID, authID ids.AuthID) *authdomain.Auth {
	return &authdomain.Auth{
		ID:        authID,
		GatewayID: gatewayID,
		Name:      "Exact Principal",
		Type:      authdomain.TypeAPIKey,
		Enabled:   true,
	}
}

// twoGitHubInstances is appUsersConsumerData with a second GitHub instance that
// holds one shared account for every caller.
func twoGitHubInstances(gatewayID ids.GatewayID, slug string, authID ids.AuthID) (*appconsumer.Data, *registrydomain.Registry, *registrydomain.Registry) {
	data := appUsersConsumerData(gatewayID, slug, authID)
	target, _ := data.MatchSlug(slug)
	perUser := target.Registries[0]
	shared := &registrydomain.Registry{
		ID:   ids.New[ids.RegistryKind](),
		Name: "GitHub (team)",
		Type: registrydomain.TypeMCP,
		MCPTarget: &registrydomain.MCPTarget{
			Code: "github",
			Auth: &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: "github", Account: registrydomain.MCPAccountShared},
		},
	}
	target.Registries = append(target.Registries, shared)
	return data, perUser, shared
}

// The page a link for a shared account opens offers nothing to connect: the
// account is the instance's and an administrator connects it.
func TestEndUserConnections_LinkRefusesAProviderServedOnlyByASharedAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appUsersConsumerData(gatewayID, "assistant", authID)
	target, _ := data.MatchSlug("assistant")
	target.Registries[0].MCPTarget.Auth.Account = registrydomain.MCPAccountShared

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(validAPIKeyAuth(gatewayID, authID), nil).Once()

	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, oauthmocks.NewConnectService(t), nil)
	_, err := svc.Link(ctx, gatewayID, "assistant", "ag_secret", "user_123", "github", "")
	require.ErrorIs(t, err, oauth.ErrSharedAccountNotLinkable)
	require.ErrorIs(t, err, commonerrors.ErrValidation)
}

// Two instances of one provider are two servers with two accounts, so the
// application can name the one it means, and the ticket is pinned to both the
// provider and that instance.
func TestEndUserConnections_LinkNamesOneInstance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data, perUser, shared := twoGitHubInstances(gatewayID, "assistant", authID)
	target, _ := data.MatchSlug("assistant")

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Times(4)
	apiKeys := appauthmocks.NewAPIKeyFinder(t)
	apiKeys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(validAPIKeyAuth(gatewayID, authID), nil).Times(4)
	tickets := oauthmocks.NewConnectService(t)
	tickets.EXPECT().
		CreateInstanceTicket(ctx, gatewayID, consumerdomain.EndUserSubject(target.Consumer.ID, "user_123"),
			appconsumer.MCPPath("assistant"), "github", "github", perUser.ID.String()).
		Return("ticket-2", nil).Once()
	// The provider alone still works while one of its instances is the user's.
	tickets.EXPECT().
		CreateProviderTicket(ctx, gatewayID, consumerdomain.EndUserSubject(target.Consumer.ID, "user_123"),
			appconsumer.MCPPath("assistant"), "github").
		Return("ticket-3", nil).Once()
	svc := oauth.NewEndUserConnectionsService(apiKeys, consumers, tickets, nil)

	link, err := svc.Link(ctx, gatewayID, "assistant", "ag_secret", "user_123", "", perUser.ID.String())
	require.NoError(t, err)
	require.Equal(t, "ticket-2", link.Ticket)
	require.Equal(t, "github", link.Provider)
	require.Equal(t, perUser.ID.String(), link.Instance)

	_, err = svc.Link(ctx, gatewayID, "assistant", "ag_secret", "user_123", "", shared.ID.String())
	require.ErrorIs(t, err, oauth.ErrSharedAccountNotLinkable)

	_, err = svc.Link(ctx, gatewayID, "assistant", "ag_secret", "user_123", "", ids.New[ids.RegistryKind]().String())
	require.ErrorIs(t, err, oauth.ErrUnknownConnectInstance)

	link, err = svc.Link(ctx, gatewayID, "assistant", "ag_secret", "user_123", "github", "")
	require.NoError(t, err)
	require.Equal(t, "ticket-3", link.Ticket)
	require.Empty(t, link.Instance)
}
