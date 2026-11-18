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
	authmocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	policymocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	backendmocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestDataFinder_WithAgentsLoadsEveryEnabledAgent(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	agent := func(name string, typ registrydomain.Type, enabled bool) *registrydomain.Registry {
		r := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gwID, Name: name, Type: typ, Enabled: enabled}
		if typ == registrydomain.TypeA2A {
			r.A2ATarget = &registrydomain.A2ATarget{ProtocolVersion: registrydomain.A2AVersion03}
		}
		return r
	}
	research := agent("research", registrydomain.TypeA2A, true)
	billing := agent("billing", registrydomain.TypeA2A, true)
	off := agent("off", registrydomain.TypeA2A, false)
	tools := agent("tools", registrydomain.TypeMCP, true)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Once()
	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Once()
	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().List(mock.Anything, registrydomain.ListFilter{GatewayID: gwID, Page: 1, Size: 100}).
		Return([]*registrydomain.Registry{research, off, tools, billing}, 4, nil).Once()
	authRepo := authmocks.NewRepository(t)

	finder := appconsumer.NewDataFinder(repo, registryRepo, policyRepo, authRepo, nil, newCacheManager(), newTestLogger(), appconsumer.WithAgents())
	data, err := finder.FindByGateway(context.Background(), gwID)
	require.NoError(t, err)

	agents := data.Agents()
	require.Len(t, agents, 2, "only the enabled A2A registries, routed to or not")
	assert.Equal(t, "billing", agents[0].Name)
	assert.Equal(t, "research", agents[1].Name)
	got, ok := data.RegistryByID(research.ID)
	assert.True(t, ok)
	assert.Same(t, research, got)
}

func TestDataFinder_PortalAgentConsumerRunsTheGlobalA2APolicies(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	h := newInertHarness(t)
	app := routableConsumer(gwID, nil)

	llmOnly := inertPolicy(gwID, "L", nameGatingSlug, nil)
	llmOnly.SetGlobal(true)
	declaresA2A := inertPolicy(gwID, "A", inertSafeSlug, nil)
	declaresA2A.SetGlobal(true)
	mcpWide := inertPolicy(gwID, "W", inertSafeSlugB, nil)
	mcpWide.SetMCPWide(true)
	attached := inertPolicy(gwID, "B", inertSafeSlugB, nil, app.ID)

	data := loadInert(t, gwID, h.reg, newTestLogger(),
		[]*domain.Consumer{app}, []*policydomain.Policy{llmOnly, declaresA2A, mcpWide, attached})

	portal := data.AgentConsumer
	require.NotNil(t, portal)
	assert.Equal(t, domain.StoreConsumerID(), portal.Consumer.ID, "tasks are owned under the Store's id")
	assert.Equal(t, domain.TypeA2A, portal.Consumer.Type)
	assert.Equal(t, domain.StoreSlug, portal.Consumer.Slug)
	assert.Equal(t, []string{"A"}, h.executedPlan(portal.PolicyPlan),
		"the global policies whose plugin supports A2A, and no MCP-wide or attached one")
	assert.Equal(t, []string{inertSafeSlug}, policySlugs(portal.Policies))
}
