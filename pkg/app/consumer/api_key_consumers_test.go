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

package consumer_test

import (
	"context"
	"testing"
	"time"

	appauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appconsumermocks "github.com/NeuralTrust/TrustGate/pkg/app/consumer/mocks"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	vaultmocks "github.com/NeuralTrust/TrustGate/pkg/domain/vault/mocks"
	"github.com/stretchr/testify/require"
)

func apiKey(gatewayID ids.GatewayID, authID ids.AuthID) *authdomain.Auth {
	return &authdomain.Auth{
		ID: authID, GatewayID: gatewayID, Name: "agent key",
		Type: authdomain.TypeAPIKey, Enabled: true,
	}
}

func consumerWith(
	gatewayID ids.GatewayID,
	slug string,
	kind domain.Type,
	identity domain.Identity,
	authIDs ...ids.AuthID,
) appconsumer.RoutableConsumer {
	return appconsumer.RoutableConsumer{Consumer: &domain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID, Name: slug, Slug: slug,
		Type: kind, Active: true, Identity: identity, AuthIDs: authIDs,
	}}
}

// An agent that calls both tools and models holds two consumers, because a
// consumer has one type. Nobody told the holder of the key which slugs those
// are — they were chosen in the console — so the key is what has to say.
func TestAPIKeyConsumers_ReportBothPlanesBehindOneKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	other := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		consumerWith(gatewayID, "support-agent", domain.TypeMCP, domain.Identity{}, authID),
		consumerWith(gatewayID, "support-agent-llm", domain.TypeLLM, domain.Identity{}, authID),
		consumerWith(gatewayID, "someone-else", domain.TypeMCP, domain.Identity{}, other),
	})

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	keys := appauthmocks.NewAPIKeyFinder(t)
	keys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(apiKey(gatewayID, authID), nil).Once()

	service, err := appconsumer.NewAPIKeyConsumers(consumers, keys, nil)
	require.NoError(t, err)
	got, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

	require.NoError(t, err)
	require.Len(t, got.Consumers, 2)
	require.Equal(t, "support-agent", got.Consumers[0].Slug)
	require.Equal(t, domain.TypeMCP, got.Consumers[0].Type)
	require.Equal(t, "support-agent-llm", got.Consumers[1].Slug)
	require.Equal(t, domain.TypeLLM, got.Consumers[1].Type)
	require.Equal(t, "agent key", got.Key.Name)
	require.Nil(t, got.Key.ExpiresAt, "a key with no expiry says so by carrying none")
}

// Which handle a client gets follows from the consumer, so the key has to
// report it: an application that acts as itself and one that acts for its
// users are used differently from the first call.
func TestAPIKeyConsumers_ReportWhichActorTheConsumerIs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		consumerWith(gatewayID, "assistant", domain.TypeMCP,
			domain.Identity{}, authID),
	})

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	keys := appauthmocks.NewAPIKeyFinder(t)
	keys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(apiKey(gatewayID, authID), nil).Once()

	service, _ := appconsumer.NewAPIKeyConsumers(consumers, keys, nil)
	got, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

	require.NoError(t, err)
	require.Equal(t, "assistant", got.Consumers[0].Slug)
}

// A key that verified but reaches nothing is not a failure: the holder proved
// it is theirs, and the empty answer is what sends them to an admin rather
// than into their own configuration.
func TestAPIKeyConsumers_AnswerEmptyWhenTheKeyReachesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		consumerWith(gatewayID, "someone-else", domain.TypeMCP, domain.Identity{}, ids.New[ids.AuthKind]()),
	})

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	keys := appauthmocks.NewAPIKeyFinder(t)
	keys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(apiKey(gatewayID, authID), nil).Once()

	service, _ := appconsumer.NewAPIKeyConsumers(consumers, keys, nil)
	got, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

	require.NoError(t, err)
	require.Empty(t, got.Consumers)
}

// One refusal for every way a key can be wrong, so the endpoint never
// confirms which gateway a key belongs to or that it exists at all.
func TestAPIKeyConsumers_RefuseEveryKeyThatIsNotThisGatewaysOwn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()

	cases := map[string]*authdomain.Auth{
		"another gateway's key": {
			ID: authID, GatewayID: ids.New[ids.GatewayKind](), Type: authdomain.TypeAPIKey, Enabled: true,
		},
		"a disabled key": {ID: authID, GatewayID: gatewayID, Type: authdomain.TypeAPIKey, Enabled: false},
		"a credential that is not an api key": {
			ID: authID, GatewayID: gatewayID, Type: authdomain.TypeOAuth2, Enabled: true,
		},
	}
	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			keys := appauthmocks.NewAPIKeyFinder(t)
			keys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(auth, nil).Once()

			service, _ := appconsumer.NewAPIKeyConsumers(appconsumermocks.NewDataFinder(t), keys, nil)
			_, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

			require.ErrorIs(t, err, appconsumer.ErrAPIKeyUnknown)
		})
	}

	t.Run("a key nobody issued", func(t *testing.T) {
		t.Parallel()
		keys := appauthmocks.NewAPIKeyFinder(t)
		keys.EXPECT().FindByAPIKey(ctx, "ag_nope").Return(nil, authdomain.ErrNotFound).Once()

		service, _ := appconsumer.NewAPIKeyConsumers(appconsumermocks.NewDataFinder(t), keys, nil)
		_, err := service.ForAPIKey(ctx, gatewayID, "ag_nope")

		require.ErrorIs(t, err, appconsumer.ErrAPIKeyUnknown)
	})

	t.Run("no key at all", func(t *testing.T) {
		t.Parallel()
		service, _ := appconsumer.NewAPIKeyConsumers(
			appconsumermocks.NewDataFinder(t), appauthmocks.NewAPIKeyFinder(t), nil,
		)
		_, err := service.ForAPIKey(ctx, gatewayID, "   ")

		require.ErrorIs(t, err, appconsumer.ErrAPIKeyUnknown)
	})
}

func forwardedRegistry(t *testing.T, gw ids.GatewayID, name string, account registrydomain.MCPAccount) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(gw, name, "", &registrydomain.MCPTarget{
		URL:  "https://mcp." + name + ".com/mcp",
		Code: "com." + name + "/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode: registrydomain.MCPAuthModeForwarded, Provider: name, ClientID: "cid",
			AuthorizeURL: "https://" + name + "/a", TokenURL: "https://" + name + "/t",
			Account: account,
		},
	})
	require.NoError(t, err)
	return reg
}

func staticRegistry(t *testing.T, gw ids.GatewayID) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(gw, "internal", "", &registrydomain.MCPTarget{
		URL:  "https://internal.acme.com/mcp",
		Auth: &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic, Header: "X-Token", Value: "s3cret"},
	})
	require.NoError(t, err)
	return reg
}

func boundConsumer(
	gatewayID ids.GatewayID,
	slug string,
	authID ids.AuthID,
	registries ...*registrydomain.Registry,
) appconsumer.RoutableConsumer {
	rc := consumerWith(gatewayID, slug, domain.TypeMCP, domain.Identity{}, authID)
	rc.Registries = registries
	return rc
}

// A request authenticated by an api key runs as the application itself, so
// this is the vault read as the application: the account an instance holds for
// everyone is there or it is not, and an instance that keeps one per caller has
// nothing for an application at all.
func TestAPIKeyConsumers_ReportWhatIsStillWaitingToBeConnected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	connected := forwardedRegistry(t, gatewayID, "confluence", registrydomain.MCPAccountShared)
	pending := forwardedRegistry(t, gatewayID, "notion", registrydomain.MCPAccountShared)
	perUser := forwardedRegistry(t, gatewayID, "github", registrydomain.MCPAccountUser)
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		boundConsumer(gatewayID, "assistant", authID, connected, pending, perUser, staticRegistry(t, gatewayID)),
	})

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	keys := appauthmocks.NewAPIKeyFinder(t)
	keys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(apiKey(gatewayID, authID), nil).Once()
	vault := vaultmocks.NewRepository(t)
	vault.EXPECT().
		Find(ctx, gatewayID, registrydomain.SharedAccountSubject(connected.ID), registrydomain.ForwardedVaultProvider(connected)).
		Return(&vaultdomain.Credential{AccountRef: "ops@acme.com", RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour)}, nil).
		Once()
	vault.EXPECT().
		Find(ctx, gatewayID, registrydomain.SharedAccountSubject(pending.ID), registrydomain.ForwardedVaultProvider(pending)).
		Return(nil, vaultdomain.ErrNotFound).
		Once()

	service, err := appconsumer.NewAPIKeyConsumers(consumers, keys, vault)
	require.NoError(t, err)
	got, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

	require.NoError(t, err)
	upstreams := got.Consumers[0].Upstreams
	require.Len(t, upstreams, 3, "a server carrying its own credential wants nothing and is not listed")

	byServer := map[string]appconsumer.KeyUpstream{}
	for _, up := range upstreams {
		byServer[up.Server] = up
	}
	require.True(t, byServer["confluence"].Connected)
	require.Empty(t, byServer["confluence"].Blocked)
	require.False(t, byServer["notion"].Connected)
	require.Equal(t, appconsumer.KeyBlockedAdministrator, byServer["notion"].Blocked,
		"no caller can connect the account every other caller rides on")
	require.Equal(t, appconsumer.KeyUpstreamUser, byServer["github"].Account)
	require.Equal(t, appconsumer.KeyBlockedEndUser, byServer["github"].Blocked,
		"an application is nobody: it names the person it acts for")
}

// A shared account that expired with nothing to refresh it with is connected
// and unusable, which is a different thing from never having been connected —
// and it is still the administrator's to fix.
func TestAPIKeyConsumers_ReportAStaleSharedAccountAsNeedingTheAdminAgain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	stale := forwardedRegistry(t, gatewayID, "notion", registrydomain.MCPAccountShared)
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		boundConsumer(gatewayID, "assistant", authID, stale),
	})

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	keys := appauthmocks.NewAPIKeyFinder(t)
	keys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(apiKey(gatewayID, authID), nil).Once()
	vault := vaultmocks.NewRepository(t)
	vault.EXPECT().
		Find(ctx, gatewayID, registrydomain.SharedAccountSubject(stale.ID), registrydomain.ForwardedVaultProvider(stale)).
		Return(&vaultdomain.Credential{ExpiresAt: time.Now().Add(-time.Hour)}, nil).
		Once()

	service, _ := appconsumer.NewAPIKeyConsumers(consumers, keys, vault)
	got, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

	require.NoError(t, err)
	up := got.Consumers[0].Upstreams[0]
	require.True(t, up.Connected)
	require.True(t, up.NeedsReconnect)
	require.Equal(t, appconsumer.KeyBlockedAdministrator, up.Blocked)
}

// A plane built without a vault cannot see the accounts, and an empty list
// there would read as "nothing to connect" — the one answer that is worse than
// no answer. It says nothing instead.
func TestAPIKeyConsumers_SayNothingAboutUpstreamsWithoutAVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		boundConsumer(gatewayID, "assistant", authID,
			forwardedRegistry(t, gatewayID, "notion", registrydomain.MCPAccountShared)),
	})

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	keys := appauthmocks.NewAPIKeyFinder(t)
	keys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(apiKey(gatewayID, authID), nil).Once()

	service, _ := appconsumer.NewAPIKeyConsumers(consumers, keys, nil)
	got, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

	require.NoError(t, err)
	require.Nil(t, got.Consumers[0].Upstreams)
}

// The key says when it retires itself, so a client can warn before the day a
// scheduled job starts answering 401.
func TestAPIKeyConsumers_CarryTheKeysOwnExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	expiry := time.Now().Add(72 * time.Hour).UTC()
	auth := apiKey(gatewayID, authID)
	auth.ExpiresAt = &expiry
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		consumerWith(gatewayID, "assistant", domain.TypeMCP, domain.Identity{}, authID),
	})

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	keys := appauthmocks.NewAPIKeyFinder(t)
	keys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(auth, nil).Once()

	service, _ := appconsumer.NewAPIKeyConsumers(consumers, keys, nil)
	got, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

	require.NoError(t, err)
	require.NotNil(t, got.Key.ExpiresAt)
	require.Equal(t, expiry, *got.Key.ExpiresAt)
}
