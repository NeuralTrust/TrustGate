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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appconsumermocks "github.com/NeuralTrust/TrustGate/pkg/app/consumer/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

// Revoking a key that two consumers hold stops both, and an admin about to do
// it has no way to find that out: the ids live on the consumer, so the question
// only reads one way round.
func TestAuthConsumers_NameEveryConsumerHoldingAKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	shared := ids.New[ids.AuthKind]()
	other := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		consumerWith(gatewayID, "support-agent-llm", domain.TypeLLM, domain.Identity{}, shared),
		consumerWith(gatewayID, "support-agent", domain.TypeMCP, domain.Identity{}, shared),
		consumerWith(gatewayID, "someone-else", domain.TypeMCP, domain.Identity{}, other),
	})
	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()

	service, err := appconsumer.NewAuthConsumers(consumers)
	require.NoError(t, err)
	got, err := service.ForAuths(ctx, gatewayID, []ids.AuthID{shared, other})

	require.NoError(t, err)
	// Sorted by slug, so a list does not reshuffle between reads.
	require.Len(t, got[shared], 2)
	require.Equal(t, "support-agent", got[shared][0].Slug)
	require.Equal(t, domain.TypeMCP, got[shared][0].Type)
	require.Equal(t, "support-agent-llm", got[shared][1].Slug)
	require.Equal(t, domain.TypeLLM, got[shared][1].Type)
	require.Len(t, got[other], 1)
}

// "Reaches nothing" is an answer. A caller that has to tell a missing key from
// an unheld one would have to know which ids it asked about, which it does.
func TestAuthConsumers_AnswerForAKeyNothingHolds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	held := ids.New[ids.AuthKind]()
	loose := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		consumerWith(gatewayID, "agent", domain.TypeMCP, domain.Identity{}, held),
	})
	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()

	service, _ := appconsumer.NewAuthConsumers(consumers)
	got, err := service.ForAuths(ctx, gatewayID, []ids.AuthID{loose})

	require.NoError(t, err)
	require.Contains(t, got, loose)
	require.Empty(t, got[loose])
}

// One read for the whole page, because the consumer data is per gateway and
// cached: asking about twenty keys costs what asking about one does.
func TestAuthConsumers_ReadTheConsumersOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	first := ids.New[ids.AuthKind]()
	second := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		consumerWith(gatewayID, "agent", domain.TypeMCP, domain.Identity{}, first, second),
	})
	consumers := appconsumermocks.NewDataFinder(t)
	consumers.EXPECT().FindByGateway(ctx, gatewayID).Return(data, nil).Once()

	service, _ := appconsumer.NewAuthConsumers(consumers)
	got, err := service.ForAuths(ctx, gatewayID, []ids.AuthID{first, second})

	require.NoError(t, err)
	require.Len(t, got[first], 1)
	require.Len(t, got[second], 1)
}

// Nothing to ask about is not a reason to read the consumers.
func TestAuthConsumers_ReadNothingForAnEmptyList(t *testing.T) {
	t.Parallel()
	service, _ := appconsumer.NewAuthConsumers(appconsumermocks.NewDataFinder(t))

	got, err := service.ForAuths(context.Background(), ids.New[ids.GatewayKind](), nil)

	require.NoError(t, err)
	require.Empty(t, got)
}
