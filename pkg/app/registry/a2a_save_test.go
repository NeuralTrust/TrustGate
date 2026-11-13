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
	"fmt"
	"testing"
	"time"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	agentCard10 = `{"name":"Travel planner","supportedInterfaces":[{"url":"https://travel.example.com/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`
	agentCard03 = `{"name":"Travel planner","url":"https://travel.example.com/rpc","protocolVersion":"0.3.0"}`
	agentARN    = "arn:aws:bedrock-agentcore:eu-west-1:123456789012:runtime/travel-abc"
)

func anonymousCards(t *testing.T) *appmocks.CardCredentials {
	t.Helper()
	creds := appmocks.NewCardCredentials(t)
	creds.EXPECT().Authorizer(mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	creds.EXPECT().CallAuthorizer(mock.Anything, mock.Anything).Return(nil, true, nil).Maybe()
	return creds
}

func servingCard(t *testing.T, cardURL, resolved, card string) *appmocks.CardFetcher {
	t.Helper()
	fetcher := appmocks.NewCardFetcher(t)
	fetcher.EXPECT().Resolve(mock.Anything, cardURL, mock.Anything).
		Return(&appregistry.FetchedCard{URL: resolved, Card: []byte(card)}, nil).Once()
	return fetcher
}

func TestCreatorA2APinsTheCard(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	fetcher := servingCard(t, "https://travel.example.com", "https://travel.example.com/.well-known/agent.json", agentCard10)
	fetcher.EXPECT().Probe(mock.Anything, "https://travel.example.com/a2a", domain.A2AVersion10, mock.Anything).Return(nil).Once()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, nil,
		appregistry.WithAgentCards(fetcher, anonymousCards(t)))

	b, err := creator.Create(context.Background(), appregistry.CreateInput{
		GatewayID: gwID, Name: "Travel planner", Type: domain.TypeA2A,
		A2ATarget: &domain.A2ATarget{CardURL: "https://travel.example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.TypeA2A, b.Type)
	assert.Equal(t, domain.A2AVersion10, b.A2ATarget.ProtocolVersion)
	assert.Equal(t, "https://travel.example.com/.well-known/agent.json", b.A2ATarget.ResolvedCardURL)
	assert.Equal(t, domain.MCPAuthModeNone, b.A2ATarget.Auth.Mode)
	assert.NotEmpty(t, b.A2ATarget.CardDigest)
	assert.False(t, b.A2ATarget.CardPinnedAt.IsZero())
}

// A card on a website that is not an agent: its endpoint does not answer
// A2A, and the agent is not saved.
func TestCreatorA2ARefusesAnEndpointThatIsNotAnAgent(t *testing.T) {
	t.Parallel()
	fetcher := servingCard(t, "https://shop.example.com", "https://shop.example.com/.well-known/agent-card.json", agentCard03)
	fetcher.EXPECT().Probe(mock.Anything, "https://travel.example.com/rpc", domain.A2AVersion03, mock.Anything).
		Return(fmt.Errorf("%w: https://travel.example.com/rpc did not answer A2A JSON-RPC: HTTP 405 (text/html)", domain.ErrAgentEndpointUnavailable)).Once()
	creator := appregistry.NewCreator(repomocks.NewRepository(t), newCacheManager(), newTestLogger(), nil, nil,
		appregistry.WithAgentCards(fetcher, anonymousCards(t)))

	_, err := creator.Create(context.Background(), appregistry.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](), Name: "Shop", Type: domain.TypeA2A,
		A2ATarget: &domain.A2ATarget{CardURL: "https://shop.example.com"},
	})
	require.ErrorIs(t, err, domain.ErrAgentEndpointUnavailable)
	assert.Contains(t, err.Error(), "HTTP 405")
}

// A credential only a user's request carries cannot ask the endpoint at
// registration: the agent is saved without the check.
func TestCreatorA2ASkipsTheCheckWithoutTheCallsCredential(t *testing.T) {
	t.Parallel()
	fetcher := servingCard(t, "https://travel.example.com", "https://travel.example.com/.well-known/agent.json", agentCard10)
	creds := appmocks.NewCardCredentials(t)
	creds.EXPECT().Authorizer(mock.Anything, mock.Anything).Return(nil, nil).Once()
	creds.EXPECT().CallAuthorizer(mock.Anything, mock.Anything).Return(nil, false, nil).Once()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, nil, appregistry.WithAgentCards(fetcher, creds))

	_, err := creator.Create(context.Background(), appregistry.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](), Name: "Travel planner", Type: domain.TypeA2A,
		A2ATarget: &domain.A2ATarget{CardURL: "https://travel.example.com"},
	})
	require.NoError(t, err)
}

func TestCreatorA2ARefusesAVersionTheCardDoesNotOffer(t *testing.T) {
	t.Parallel()
	fetcher := servingCard(t, "https://travel.example.com", "https://travel.example.com/.well-known/agent-card.json", agentCard03)
	creator := appregistry.NewCreator(repomocks.NewRepository(t), newCacheManager(), newTestLogger(), nil, nil,
		appregistry.WithAgentCards(fetcher, anonymousCards(t)))

	_, err := creator.Create(context.Background(), appregistry.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](), Name: "t", Type: domain.TypeA2A,
		A2ATarget: &domain.A2ATarget{CardURL: "https://travel.example.com", ProtocolVersion: domain.A2AVersion10},
	})
	require.ErrorIs(t, err, domain.ErrAgentVersionUnsupported)
	assert.ErrorContains(t, err, `["0.3"]`)
}

func TestCreatorA2AValidatesBeforeFetching(t *testing.T) {
	t.Parallel()
	creator := appregistry.NewCreator(repomocks.NewRepository(t), newCacheManager(), newTestLogger(), nil, nil,
		appregistry.WithAgentCards(appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t)))

	_, err := creator.Create(context.Background(), appregistry.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](), Name: "t", Type: domain.TypeA2A,
		A2ATarget: &domain.A2ATarget{CardURL: "https://travel.example.com", Headers: map[string]string{"Authorization": "Bearer x"}},
	})
	require.ErrorIs(t, err, domain.ErrInvalidRegistry)
	assert.ErrorContains(t, err, "Authorization")
}

func TestCreatorA2ARequiresExternalIDOnASharedGateway(t *testing.T) {
	t.Parallel()
	gw, err := gatewaydomain.New("shared")
	require.NoError(t, err)
	gateways := gatewaymocks.NewRepository(t)
	gateways.EXPECT().FindByID(mock.Anything, gw.ID).Return(gw, nil).Once()
	creator := appregistry.NewCreator(repomocks.NewRepository(t), newCacheManager(), newTestLogger(), nil, nil,
		appregistry.WithAgentCards(appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t)),
		appregistry.WithSharedDataPlane(gateways))

	_, err = creator.Create(context.Background(), appregistry.CreateInput{
		GatewayID: gw.ID, Name: "t", Type: domain.TypeA2A,
		A2ATarget: &domain.A2ATarget{
			Provider:         domain.A2AProviderBedrockAgentCore,
			BedrockAgentCore: &domain.AgentCoreLocator{RuntimeARN: agentARN},
			Auth:             &domain.MCPAuth{Mode: domain.A2AAuthModeCloud},
			CloudAuth: &domain.A2ACloudAuth{AWS: &domain.A2AAWSAuth{
				AWSAuth: domain.AWSAuth{UseRole: true, Role: "arn:aws:iam::123456789012:role/tg-agents"},
			}},
		},
	})
	require.ErrorIs(t, err, domain.ErrInvalidRegistry)
	assert.ErrorContains(t, err, "external_id")
}

func pinnedA2ARegistry(t *testing.T) *domain.Registry {
	t.Helper()
	target := &domain.A2ATarget{
		CardURL: "https://travel.example.com",
		Headers: map[string]string{"X-Tenant": "acme-secret"},
		Auth:    &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "X-Key", Value: "stored-key"},
	}
	target.Normalize()
	require.NoError(t, target.Pin("https://travel.example.com/.well-known/agent-card.json", []byte(agentCard10), time.Now().Add(-time.Hour)))
	reg, err := domain.NewA2ARegistry(ids.New[ids.GatewayKind](), "Travel planner", "", target)
	require.NoError(t, err)
	return reg
}

func expectSavedUpdate(t *testing.T, existing *domain.Registry) (*repomocks.Repository, *cachemocks.EventPublisher) {
	t.Helper()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateRegistryCacheEvent{GatewayID: existing.GatewayID.String(), RegistryID: existing.ID.String()}).
		Return(nil).Once()
	return repo, publisher
}

func TestUpdaterA2AHeadersOnlyDoesNotFetch(t *testing.T) {
	t.Parallel()
	existing := pinnedA2ARegistry(t)
	digest, pinnedAt := existing.A2ATarget.CardDigest, existing.A2ATarget.CardPinnedAt
	repo, publisher := expectSavedUpdate(t, existing)
	updater := appregistry.NewUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil, nil,
		appregistry.WithAgentCards(appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t)))

	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID: existing.ID,
		A2ATarget: &domain.A2ATarget{
			Headers: map[string]string{"X-Tenant": secret.Mask("acme-secret"), "X-Region": "eu"},
			Auth:    &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "X-Key", Value: secret.Mask("stored-key")},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, digest, got.A2ATarget.CardDigest)
	assert.Equal(t, pinnedAt, got.A2ATarget.CardPinnedAt)
	assert.Equal(t, "acme-secret", got.A2ATarget.Headers["X-Tenant"])
	assert.Equal(t, "eu", got.A2ATarget.Headers["X-Region"])
	assert.Equal(t, "stored-key", got.A2ATarget.Auth.Value)
	assert.Equal(t, "https://travel.example.com", got.A2ATarget.CardURL)
}

func TestUpdaterA2ARepinsWhenTheCardURLChanges(t *testing.T) {
	t.Parallel()
	existing := pinnedA2ARegistry(t)
	repo, publisher := expectSavedUpdate(t, existing)
	fetcher := servingCard(t, "https://planner.example.com", "https://planner.example.com/.well-known/agent-card.json", agentCard03)
	fetcher.EXPECT().Probe(mock.Anything, "https://travel.example.com/rpc", domain.A2AVersion03, mock.Anything).Return(nil).Once()
	updater := appregistry.NewUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil, nil,
		appregistry.WithAgentCards(fetcher, anonymousCards(t)))

	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:        existing.ID,
		A2ATarget: &domain.A2ATarget{CardURL: "https://planner.example.com", ProtocolVersion: domain.A2AVersion03},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.A2AVersion03, got.A2ATarget.ProtocolVersion)
	assert.Equal(t, "https://planner.example.com/.well-known/agent-card.json", got.A2ATarget.ResolvedCardURL)
	assert.Equal(t, "https://travel.example.com/rpc", got.A2ATarget.Endpoint())
}

func TestUpdaterA2ARefusesAProviderChange(t *testing.T) {
	t.Parallel()
	existing := pinnedA2ARegistry(t)
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	updater := appregistry.NewUpdater(repo, newCacheManager(), nil, newTestLogger(), nil, nil)

	_, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:        existing.ID,
		A2ATarget: &domain.A2ATarget{Provider: domain.A2AProviderAzureFoundry},
	})
	require.ErrorIs(t, err, domain.ErrInvalidRegistry)
	assert.ErrorContains(t, err, "cannot change provider")
}

func TestUpdaterA2ADropsCloudAuthTheNewModeDoesNotUse(t *testing.T) {
	t.Parallel()
	gw, _ := gatewayOn(t, gatewaydomain.DataPlaneDedicated)
	existing := storedCloudAgent(gw, cloudTarget(domain.A2AProviderBedrockAgentCore, &domain.A2ACloudAuth{AWS: &domain.A2AAWSAuth{
		AWSAuth: domain.AWSAuth{AccessKeyID: "AKIA", SecretAccessKey: "stored-secret"},
	}}))
	repo, publisher := expectSavedUpdate(t, existing)
	updater := appregistry.NewUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil, nil,
		appregistry.WithAgentCards(appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t)))

	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID: existing.ID,
		A2ATarget: &domain.A2ATarget{Auth: &domain.MCPAuth{
			Mode: domain.MCPAuthModeClientCredentials, ClientID: "app", ClientSecret: "app-secret", TokenURL: "https://idp.example.com/token",
		}},
	})
	require.NoError(t, err)
	assert.Nil(t, got.A2ATarget.CloudAuth)
	assert.Equal(t, domain.MCPAuthModeClientCredentials, got.A2ATarget.Auth.Mode)
}

func TestUpdaterA2AKeepsCloudAuthWhileTheModeUsesIt(t *testing.T) {
	t.Parallel()
	gw, _ := gatewayOn(t, gatewaydomain.DataPlaneDedicated)
	existing := storedCloudAgent(gw, explicitCloudTarget())
	repo, publisher := expectSavedUpdate(t, existing)
	updater := appregistry.NewUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil, nil,
		appregistry.WithAgentCards(appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t)))

	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:        existing.ID,
		A2ATarget: &domain.A2ATarget{Headers: map[string]string{"X-Region": "eu"}},
	})
	require.NoError(t, err)
	require.NotNil(t, got.A2ATarget.CloudAuth)
	assert.Equal(t, "s3cret", got.A2ATarget.CloudAuth.Azure.ClientSecret)
}
