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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// A Databricks agent publishes no card: the preview is the card the gateway
// builds, and nothing is read from the agent, with or without a credential.
func TestPreviewBuildsTheCardOfAnAgentWithNone(t *testing.T) {
	t.Parallel()
	gw, gateways := gatewayOn(t, gatewaydomain.DataPlaneHosted)
	cards := appregistry.NewPreviewAgentCard(
		appregistry.WithAgentCards(appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t)), appregistry.WithSharedDataPlane(gateways))

	got, err := cards.Preview(context.Background(), gw.ID, &domain.A2ATarget{
		Provider:   domain.A2AProviderDatabricks,
		Databricks: &domain.DatabricksLocator{WorkspaceURL: "https://acme.cloud.databricks.com", ServingEndpoint: "agents_flats"},
		Auth:       &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer dapi"},
	})
	require.NoError(t, err)
	assert.Equal(t, []domain.A2AProtocolVersion{domain.A2AVersion03}, got.Versions)
	assert.Contains(t, string(got.Card), `"name":"agents_flats"`)
	assert.Empty(t, got.ResolvedCardURL)
}
