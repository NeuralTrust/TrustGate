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

package registry_test

import (
	"context"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	pinnedCardURL = "https://travel.example.com/.well-known/agent-card.json"
	cardNewSkill  = `{"name":"Travel planner","supportedInterfaces":[{"url":"https://travel.example.com/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],"skills":[{"id":"refund_invoice","name":"Refund"}]}`
)

func liveCard(t *testing.T, card string) *appmocks.CardFetcher {
	t.Helper()
	fetcher := appmocks.NewCardFetcher(t)
	fetcher.EXPECT().Fetch(mock.Anything, pinnedCardURL, mock.Anything).
		Return(&appregistry.FetchedCard{URL: pinnedCardURL, Card: []byte(card)}, nil)
	return fetcher
}

func storedAgent(t *testing.T, reg *domain.Registry) *repomocks.Repository {
	t.Helper()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, reg.ID).Return(reg, nil)
	return repo
}

func newAgentCard(repo domain.Repository, publisher cache.EventPublisher, fetcher appregistry.CardFetcher, creds appregistry.CardCredentials) appregistry.AgentCard {
	return appregistry.NewAgentCard(repo, newCacheManager(), publisher, newTestLogger(), nil, appregistry.WithAgentCards(fetcher, creds))
}

func digestOf(t *testing.T, card string) string {
	t.Helper()
	d, err := domain.CardDigest([]byte(card))
	require.NoError(t, err)
	return d
}

func TestAgentCardPreviewOfAGRPCOnlyCard(t *testing.T) {
	t.Parallel()
	grpc := `{"name":"Travel planner","supportedInterfaces":[{"url":"https://travel.example.com","protocolBinding":"GRPC","protocolVersion":"1.0"}]}`
	fetcher := appmocks.NewCardFetcher(t)
	fetcher.EXPECT().Resolve(mock.Anything, "https://travel.example.com", mock.Anything).
		Return(&appregistry.FetchedCard{URL: pinnedCardURL, Card: []byte(grpc)}, nil).Once()
	cards := newAgentCard(repomocks.NewRepository(t), nil, fetcher, anonymousCards(t))

	got, err := cards.Preview(context.Background(), ids.New[ids.GatewayKind](), &domain.A2ATarget{CardURL: "https://travel.example.com"})
	require.NoError(t, err)
	assert.Empty(t, got.Versions)
	assert.Empty(t, got.DefaultVersion)
	assert.Equal(t, digestOf(t, grpc), got.CardDigest)
	assert.Equal(t, pinnedCardURL, got.ResolvedCardURL)
}

func TestAgentCardPreviewRefusesACardWithoutName(t *testing.T) {
	t.Parallel()
	fetcher := appmocks.NewCardFetcher(t)
	fetcher.EXPECT().Resolve(mock.Anything, mock.Anything, mock.Anything).
		Return(&appregistry.FetchedCard{URL: pinnedCardURL, Card: []byte(`{"skills":[]}`)}, nil).Once()
	cards := newAgentCard(repomocks.NewRepository(t), nil, fetcher, anonymousCards(t))

	_, err := cards.Preview(context.Background(), ids.New[ids.GatewayKind](), &domain.A2ATarget{CardURL: "https://travel.example.com"})
	require.ErrorIs(t, err, domain.ErrAgentCardUnavailable)
}

func TestAgentCardRefreshReportsANewSkill(t *testing.T) {
	t.Parallel()
	reg := pinnedA2ARegistry(t)
	pinned := reg.A2ATarget.CardDigest
	cards := newAgentCard(storedAgent(t, reg), nil, liveCard(t, cardNewSkill), anonymousCards(t))

	got, err := cards.Refresh(context.Background(), reg.GatewayID, reg.ID)
	require.NoError(t, err)
	assert.True(t, got.Changed)
	assert.Equal(t, []string{"skills"}, got.ChangedFields)
	assert.Equal(t, []string{"refund_invoice"}, got.SkillsAdded)
	assert.Empty(t, got.SkillsRemoved)
	assert.Equal(t, pinned, got.PinnedDigest)
	assert.Equal(t, pinned, reg.A2ATarget.CardDigest)
}

func TestAgentCardRefusesAnotherGatewayAndNonAgents(t *testing.T) {
	t.Parallel()
	reg := pinnedA2ARegistry(t)
	cards := newAgentCard(storedAgent(t, reg), nil, appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t))
	_, err := cards.Refresh(context.Background(), ids.New[ids.GatewayKind](), reg.ID)
	require.ErrorIs(t, err, domain.ErrNotFound)

	llm, err := domain.NewLLMRegistry(reg.GatewayID, "llm", "", &domain.LLMTarget{Provider: "openai", Auth: domain.NewAPIKeyAuth("sk")})
	require.NoError(t, err)
	cards = newAgentCard(storedAgent(t, llm), nil, appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t))
	_, err = cards.Approve(context.Background(), llm.GatewayID, llm.ID, "sha256:x")
	require.ErrorIs(t, err, appregistry.ErrNotAgentRegistry)
}

func TestAgentCardApprovePinsTheReviewedCard(t *testing.T) {
	t.Parallel()
	reg := pinnedA2ARegistry(t)
	repo := storedAgent(t, reg)
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.A2ATarget.CardDigest == digestOf(t, cardNewSkill)
	})).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateRegistryCacheEvent{GatewayID: reg.GatewayID.String(), RegistryID: reg.ID.String()}).
		Return(nil).Once()
	cards := newAgentCard(repo, publisher, liveCard(t, cardNewSkill), anonymousCards(t))

	got, err := cards.Approve(context.Background(), reg.GatewayID, reg.ID, digestOf(t, cardNewSkill))
	require.NoError(t, err)
	assert.JSONEq(t, cardNewSkill, string(got.A2ATarget.Card))
}

func TestAgentCardApproveOfAMovedCardConflicts(t *testing.T) {
	t.Parallel()
	reg := pinnedA2ARegistry(t)
	pinned := reg.A2ATarget.CardDigest
	cards := newAgentCard(storedAgent(t, reg), nil, liveCard(t, cardNewSkill), anonymousCards(t))

	_, err := cards.Approve(context.Background(), reg.GatewayID, reg.ID, "sha256:reviewed-earlier")
	require.ErrorIs(t, err, appregistry.ErrAgentCardChanged)
	assert.Equal(t, pinned, reg.A2ATarget.CardDigest)
}

func TestAgentCardApproveOfTheDroppedVersionIsRefused(t *testing.T) {
	t.Parallel()
	reg := pinnedA2ARegistry(t)
	cards := newAgentCard(storedAgent(t, reg), nil, liveCard(t, agentCard03), anonymousCards(t))

	_, err := cards.Approve(context.Background(), reg.GatewayID, reg.ID, digestOf(t, agentCard03))
	require.ErrorIs(t, err, domain.ErrAgentVersionUnsupported)
}

func TestAgentCardApproveOfThePinnedDigestIsANoOp(t *testing.T) {
	t.Parallel()
	reg := pinnedA2ARegistry(t)
	cards := newAgentCard(storedAgent(t, reg), nil, appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t))

	got, err := cards.Approve(context.Background(), reg.GatewayID, reg.ID, reg.A2ATarget.CardDigest)
	require.NoError(t, err)
	assert.Equal(t, reg.A2ATarget.CardDigest, got.A2ATarget.CardDigest)
}
