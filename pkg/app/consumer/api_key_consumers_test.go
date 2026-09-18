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

	appauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appconsumermocks "github.com/NeuralTrust/TrustGate/pkg/app/consumer/mocks"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
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

	service, err := appconsumer.NewAPIKeyConsumers(consumers, keys)
	require.NoError(t, err)
	got, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, "support-agent", got[0].Slug)
	require.Equal(t, domain.TypeMCP, got[0].Type)
	require.Equal(t, "support-agent-llm", got[1].Slug)
	require.Equal(t, domain.TypeLLM, got[1].Type)
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
			domain.Identity{ActsForUsers: true, Source: domain.IdentitySourceApp}, authID),
	})

	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()
	keys := appauthmocks.NewAPIKeyFinder(t)
	keys.EXPECT().FindByAPIKey(ctx, "ag_secret").Return(apiKey(gatewayID, authID), nil).Once()

	service, _ := appconsumer.NewAPIKeyConsumers(consumers, keys)
	got, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

	require.NoError(t, err)
	require.True(t, got[0].ActsForUsers)
	require.Equal(t, string(domain.IdentitySourceApp), got[0].IdentitySource)
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

	service, _ := appconsumer.NewAPIKeyConsumers(consumers, keys)
	got, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

	require.NoError(t, err)
	require.Empty(t, got)
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

			service, _ := appconsumer.NewAPIKeyConsumers(appconsumermocks.NewDataFinder(t), keys)
			_, err := service.ForAPIKey(ctx, gatewayID, "ag_secret")

			require.ErrorIs(t, err, appconsumer.ErrAPIKeyUnknown)
		})
	}

	t.Run("a key nobody issued", func(t *testing.T) {
		t.Parallel()
		keys := appauthmocks.NewAPIKeyFinder(t)
		keys.EXPECT().FindByAPIKey(ctx, "ag_nope").Return(nil, authdomain.ErrNotFound).Once()

		service, _ := appconsumer.NewAPIKeyConsumers(appconsumermocks.NewDataFinder(t), keys)
		_, err := service.ForAPIKey(ctx, gatewayID, "ag_nope")

		require.ErrorIs(t, err, appconsumer.ErrAPIKeyUnknown)
	})

	t.Run("no key at all", func(t *testing.T) {
		t.Parallel()
		service, _ := appconsumer.NewAPIKeyConsumers(
			appconsumermocks.NewDataFinder(t), appauthmocks.NewAPIKeyFinder(t),
		)
		_, err := service.ForAPIKey(ctx, gatewayID, "   ")

		require.ErrorIs(t, err, appconsumer.ErrAPIKeyUnknown)
	})
}
