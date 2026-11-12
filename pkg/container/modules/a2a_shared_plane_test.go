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

package modules

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type recordingSigner struct{ calls int }

func (s *recordingSigner) Sign(context.Context, *domain.A2ATarget, appa2a.CacheKey, *http.Request) error {
	s.calls++
	return nil
}

func ambientVertexTarget() *domain.A2ATarget {
	return &domain.A2ATarget{
		Provider:          domain.A2AProviderVertexAgentEngine,
		VertexAgentEngine: &domain.VertexLocator{Project: "acme-agents", Location: "europe-west1", ReasoningEngineID: "1234567890"},
		Auth:              &domain.MCPAuth{Mode: domain.A2AAuthModeCloud},
		CloudAuth:         &domain.A2ACloudAuth{GCP: &domain.A2AGCPAuth{}},
	}
}

func TestSaaSDeploymentEnablesSharedDataPlaneChecks(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.ConfigSync.DeploymentType = config.InstanceDeploymentSaaS
	target := ambientVertexTarget()

	gw, err := gatewaydomain.New("tenant")
	require.NoError(t, err)
	gw.Entitlements.DataPlane = gatewaydomain.DataPlaneHosted
	gateways := gatewaymocks.NewRepository(t)
	gateways.EXPECT().FindByID(mock.Anything, gw.ID).Return(gw, nil).Once()
	creator := appregistry.NewCreator(
		repomocks.NewRepository(t), cache.NewTTLMapManager(time.Hour), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil,
		registrySaveParams{
			Config:          cfg,
			Gateways:        gateways,
			CardFetcher:     appmocks.NewCardFetcher(t),
			CardCredentials: appmocks.NewCardCredentials(t),
		}.options(nil)...,
	)
	_, err = creator.Create(context.Background(), appregistry.CreateInput{
		GatewayID: gw.ID, Name: "planner", Type: domain.TypeA2A, A2ATarget: target,
	})
	require.ErrorIs(t, err, domain.ErrInvalidRegistry)

	signer := &recordingSigner{}
	reg := &domain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		A2ATarget: target,
	}
	creds := appa2a.NewCredentials(nil, nil, signer, false, a2aCredentialOptions(cfg)...)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://travel.example/a2a", http.NoBody)
	require.NoError(t, err)
	err = creds.Sign(context.Background(), reg, req)
	require.ErrorIs(t, err, domain.ErrInvalidRegistry)
	require.Zero(t, signer.calls)

	cfg.ConfigSync.DeploymentType = config.InstanceDeploymentSelfHosted
	off := appa2a.NewCredentials(nil, nil, signer, false, a2aCredentialOptions(cfg)...)
	require.NoError(t, off.Sign(context.Background(), reg, req))
	require.Equal(t, 1, signer.calls)
}
