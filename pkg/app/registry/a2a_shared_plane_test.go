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
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const foundryCard = `{"name":"Planner"}`

func cloudTarget(provider domain.A2AProvider, cloud *domain.A2ACloudAuth) *domain.A2ATarget {
	t := &domain.A2ATarget{Provider: provider, Auth: &domain.MCPAuth{Mode: domain.A2AAuthModeCloud}, CloudAuth: cloud}
	switch provider {
	case domain.A2AProviderBedrockAgentCore:
		t.BedrockAgentCore = &domain.AgentCoreLocator{RuntimeARN: agentARN}
	case domain.A2AProviderAzureFoundry:
		t.AzureFoundry = &domain.FoundryLocator{ProjectEndpoint: "https://acme.services.ai.azure.com/api/projects/travel", AgentName: "planner"}
	case domain.A2AProviderVertexAgentEngine:
		t.VertexAgentEngine = &domain.VertexLocator{Project: "acme-agents", Location: "europe-west1", ReasoningEngineID: "1234567890"}
	case domain.A2AProviderGeneric:
	}
	t.Normalize()
	return t
}

var ambientCloudTargets = map[string]func() *domain.A2ATarget{
	"aws default chain": func() *domain.A2ATarget {
		return cloudTarget(domain.A2AProviderBedrockAgentCore, &domain.A2ACloudAuth{AWS: &domain.A2AAWSAuth{}})
	},
	"azure managed identity": func() *domain.A2ATarget {
		return cloudTarget(domain.A2AProviderAzureFoundry, &domain.A2ACloudAuth{Azure: &domain.AzureAuth{UseManagedIdentity: true}})
	},
	"gcp application default credentials": func() *domain.A2ATarget {
		return cloudTarget(domain.A2AProviderVertexAgentEngine, &domain.A2ACloudAuth{GCP: &domain.A2AGCPAuth{}})
	},
	"gcp impersonation": func() *domain.A2ATarget {
		return cloudTarget(domain.A2AProviderVertexAgentEngine, &domain.A2ACloudAuth{GCP: &domain.A2AGCPAuth{
			ImpersonateServiceAccount: "sa@other-project.iam.gserviceaccount.com",
		}})
	},
}

func explicitCloudTarget() *domain.A2ATarget {
	return cloudTarget(domain.A2AProviderAzureFoundry, &domain.A2ACloudAuth{
		Azure: &domain.AzureAuth{TenantID: "tenant", ClientID: "client", ClientSecret: "s3cret"},
	})
}

func gatewayOn(t *testing.T, dataPlane string) (*gatewaydomain.Gateway, *gatewaymocks.Repository) {
	t.Helper()
	gw, err := gatewaydomain.New("tenant")
	require.NoError(t, err)
	gw.Entitlements.DataPlane = dataPlane
	gateways := gatewaymocks.NewRepository(t)
	gateways.EXPECT().FindByID(mock.Anything, gw.ID).Return(gw, nil).Maybe()
	return gw, gateways
}

func storedCloudAgent(gw *gatewaydomain.Gateway, target *domain.A2ATarget) *domain.Registry {
	target.Card = []byte(foundryCard)
	target.CardDigest = "sha256:stored"
	return &domain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw.ID, Name: "agent", Type: domain.TypeA2A, A2ATarget: target}
}

func TestSharedDataPlaneRefusesAmbientCloudCredentialsOnEveryAgentOperation(t *testing.T) {
	t.Parallel()
	for name, build := range ambientCloudTargets {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gw, gateways := gatewayOn(t, gatewaydomain.DataPlaneHosted)
			fetcher := appmocks.NewCardFetcher(t)
			creds := appmocks.NewCardCredentials(t)
			shared := appregistry.WithSharedDataPlane(gateways)
			cards := appregistry.WithAgentCards(fetcher, creds)
			ctx := context.Background()

			t.Run("create", func(t *testing.T) {
				creator := appregistry.NewCreator(repomocks.NewRepository(t), newCacheManager(), newTestLogger(), nil, nil, cards, shared)
				_, err := creator.Create(ctx, appregistry.CreateInput{GatewayID: gw.ID, Name: "t", Type: domain.TypeA2A, A2ATarget: build()})
				require.ErrorIs(t, err, domain.ErrInvalidRegistry)
			})

			t.Run("preview", func(t *testing.T) {
				_, err := appregistry.NewPreviewAgentCard(cards, shared).
					Preview(ctx, gw.ID, build())
				require.ErrorIs(t, err, domain.ErrInvalidRegistry)
			})

			t.Run("refresh", func(t *testing.T) {
				reg := storedCloudAgent(gw, build())
				_, err := appregistry.NewRefreshAgentCard(storedAgent(t, reg), nil, newCacheManager(), nil, newTestLogger(), cards, shared).
					Refresh(ctx, gw.ID, reg.ID)
				require.ErrorIs(t, err, domain.ErrInvalidRegistry)
			})

			t.Run("approve", func(t *testing.T) {
				reg := storedCloudAgent(gw, build())
				_, err := appregistry.NewApproveAgentCard(storedAgent(t, reg), nil, newCacheManager(), nil, newTestLogger(), nil, cards, shared).
					Approve(ctx, gw.ID, reg.ID, "sha256:reviewed")
				require.ErrorIs(t, err, domain.ErrInvalidRegistry)
			})
		})
	}
}

func TestSharedDataPlaneRefusesAnAmbientCredentialSetOnUpdate(t *testing.T) {
	t.Parallel()
	gw, gateways := gatewayOn(t, gatewaydomain.DataPlaneHosted)
	existing := storedCloudAgent(gw, explicitCloudTarget())
	updater := appregistry.NewUpdater(storedAgent(t, existing), newCacheManager(), nil, newTestLogger(), nil, nil,
		appregistry.WithAgentCards(appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t)),
		appregistry.WithSharedDataPlane(gateways))

	_, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID: existing.ID,
		A2ATarget: &domain.A2ATarget{
			Auth:      &domain.MCPAuth{Mode: domain.A2AAuthModeCloud},
			CloudAuth: &domain.A2ACloudAuth{Azure: &domain.AzureAuth{UseManagedIdentity: true}},
		},
	})
	require.ErrorIs(t, err, domain.ErrInvalidRegistry)
	assert.ErrorContains(t, err, "managed identity")
}

func TestSharedDataPlaneAllowsExplicitCloudCredentials(t *testing.T) {
	t.Parallel()
	gw, gateways := gatewayOn(t, gatewaydomain.DataPlaneHosted)
	target := explicitCloudTarget()
	fetcher := appmocks.NewCardFetcher(t)
	fetcher.EXPECT().Fetch(mock.Anything, target.CardLocation(), mock.Anything).
		Return(&appregistry.FetchedCard{URL: target.CardLocation(), Card: []byte(foundryCard)}, nil).Once()
	cards := appregistry.NewPreviewAgentCard(
		appregistry.WithAgentCards(fetcher, anonymousCards(t)), appregistry.WithSharedDataPlane(gateways))

	got, err := cards.Preview(context.Background(), gw.ID, target)
	require.NoError(t, err)
	assert.Equal(t, target.CardLocation(), got.ResolvedCardURL)
}

func TestOwnDataPlaneKeepsAmbientCloudCredentials(t *testing.T) {
	t.Parallel()
	for _, dataPlane := range []string{gatewaydomain.DataPlaneDedicated, gatewaydomain.DataPlaneHybrid} {
		for name, build := range ambientCloudTargets {
			t.Run(dataPlane+"/"+name, func(t *testing.T) {
				t.Parallel()
				gw, gateways := gatewayOn(t, dataPlane)
				target := build()
				fetcher := appmocks.NewCardFetcher(t)
				fetcher.EXPECT().Fetch(mock.Anything, target.CardLocation(), mock.Anything).
					Return(&appregistry.FetchedCard{URL: target.CardLocation(), Card: []byte(foundryCard)}, nil).Once()
				cards := appregistry.NewPreviewAgentCard(
					appregistry.WithAgentCards(fetcher, anonymousCards(t)), appregistry.WithSharedDataPlane(gateways))

				_, err := cards.Preview(context.Background(), gw.ID, target)
				require.NoError(t, err)
			})
		}
	}
}

func TestSelfHostedDeploymentKeepsAmbientCloudCredentials(t *testing.T) {
	t.Parallel()
	for name, build := range ambientCloudTargets {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			target := build()
			fetcher := appmocks.NewCardFetcher(t)
			fetcher.EXPECT().Fetch(mock.Anything, target.CardLocation(), mock.Anything).
				Return(&appregistry.FetchedCard{URL: target.CardLocation(), Card: []byte(foundryCard)}, nil).Once()
			cards := appregistry.NewPreviewAgentCard(
				appregistry.WithAgentCards(fetcher, anonymousCards(t)))

			_, err := cards.Preview(context.Background(), ids.New[ids.GatewayKind](), target)
			require.NoError(t, err)
		})
	}
}

func TestSharedDataPlaneWithoutAGatewayLookupAppliesTheRules(t *testing.T) {
	t.Parallel()
	cards := appregistry.NewPreviewAgentCard(
		appregistry.WithAgentCards(appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t)), appregistry.WithSharedDataPlane(nil))

	_, err := cards.Preview(context.Background(), ids.New[ids.GatewayKind](), ambientCloudTargets["aws default chain"]())
	require.ErrorIs(t, err, domain.ErrInvalidRegistry)
}
