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
	"errors"
	"fmt"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGroupedFinder_GroupsFiltersAndOrdersRegistries(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	openAIAlphaFirst := groupedRegistry("00000000-0000-0000-0000-000000000001", gatewayID, "alpha", domain.TypeLLM, "openai")
	openAIAlphaSecond := groupedRegistry("00000000-0000-0000-0000-000000000002", gatewayID, "Alpha", domain.TypeLLM, "openai")
	openAIBeta := groupedRegistry("00000000-0000-0000-0000-000000000003", gatewayID, "beta", domain.TypeLLM, "openai")
	openAILegacy := groupedRegistry("00000000-0000-0000-0000-000000000004", gatewayID, "Gamma", "", "openai")
	anthropic := groupedRegistry("00000000-0000-0000-0000-000000000005", gatewayID, "Claude", domain.TypeLLM, "anthropic")
	mcp := groupedRegistry("00000000-0000-0000-0000-000000000006", gatewayID, "MCP", domain.TypeMCP, "")
	unconfigured := groupedRegistry("00000000-0000-0000-0000-000000000007", gatewayID, "Missing", domain.TypeLLM, "")
	items := []*domain.Registry{openAIBeta, mcp, anthropic, openAIAlphaSecond, unconfigured, openAILegacy, openAIAlphaFirst}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		List(mock.Anything, domain.ListFilter{GatewayID: gatewayID, Page: 1, Size: 100}).
		Return(items, len(items), nil).
		Once()

	result, err := appregistry.NewGroupedFinder(repo).Find(context.Background(), gatewayID)

	require.NoError(t, err)
	require.Len(t, result.Groups, 2)
	assert.Equal(t, 5, result.TotalInstances)
	assert.Equal(t, "anthropic", result.Groups[0].Provider)
	assert.Equal(t, []*domain.Registry{anthropic}, result.Groups[0].Instances)
	assert.Equal(t, "openai", result.Groups[1].Provider)
	assert.Equal(t, []*domain.Registry{openAIAlphaFirst, openAIAlphaSecond, openAIBeta, openAILegacy}, result.Groups[1].Instances)
}

func TestGroupedFinder_PaginatesUntilRepositoryTotal(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	first := groupedRegistry("00000000-0000-0000-0000-000000000001", gatewayID, "First", domain.TypeLLM, "openai")
	second := groupedRegistry("00000000-0000-0000-0000-000000000002", gatewayID, "Second", domain.TypeLLM, "openai")

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		List(mock.Anything, domain.ListFilter{GatewayID: gatewayID, Page: 1, Size: 100}).
		Return([]*domain.Registry{second}, 2, nil).
		Once()
	repo.EXPECT().
		List(mock.Anything, domain.ListFilter{GatewayID: gatewayID, Page: 2, Size: 100}).
		Return([]*domain.Registry{first}, 2, nil).
		Once()

	result, err := appregistry.NewGroupedFinder(repo).Find(context.Background(), gatewayID)

	require.NoError(t, err)
	require.Len(t, result.Groups, 1)
	assert.Equal(t, []*domain.Registry{first, second}, result.Groups[0].Instances)
	assert.Equal(t, 2, result.TotalInstances)
}

func TestGroupedFinder_AllowsExactlyMaximumRegistryCount(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	firstPage := groupedRegistries(gatewayID, 0, 100)
	secondPage := groupedRegistries(gatewayID, 100, 100)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		List(mock.Anything, domain.ListFilter{GatewayID: gatewayID, Page: 1, Size: 100}).
		Return(firstPage, appregistry.MaxGroupedRegistryCount, nil).
		Once()
	repo.EXPECT().
		List(mock.Anything, domain.ListFilter{GatewayID: gatewayID, Page: 2, Size: 100}).
		Return(secondPage, appregistry.MaxGroupedRegistryCount, nil).
		Once()

	result, err := appregistry.NewGroupedFinder(repo).Find(context.Background(), gatewayID)

	require.NoError(t, err)
	assert.Equal(t, appregistry.MaxGroupedRegistryCount, result.TotalInstances)
	require.Len(t, result.Groups, 1)
	assert.Len(t, result.Groups[0].Instances, appregistry.MaxGroupedRegistryCount)
}

func TestGroupedFinder_RejectsRepositoryTotalAboveMaximum(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		List(mock.Anything, domain.ListFilter{GatewayID: gatewayID, Page: 1, Size: 100}).
		Return(nil, appregistry.MaxGroupedRegistryCount+1, nil).
		Once()

	result, err := appregistry.NewGroupedFinder(repo).Find(context.Background(), gatewayID)

	assert.ErrorIs(t, err, commonerrors.ErrResultTooLarge)
	assert.Empty(t, result.Groups)
}

func TestGroupedFinder_StopsBeforeFirstPageWhenContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	repo := repomocks.NewRepository(t)

	result, err := appregistry.NewGroupedFinder(repo).Find(ctx, ids.New[ids.GatewayKind]())

	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, result.Groups)
}

func TestGroupedFinder_StopsAfterPageWhenContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		List(mock.Anything, domain.ListFilter{GatewayID: gatewayID, Page: 1, Size: 100}).
		Run(func(context.Context, domain.ListFilter) {
			cancel()
		}).
		Return(groupedRegistries(gatewayID, 0, 1), 2, nil).
		Once()

	result, err := appregistry.NewGroupedFinder(repo).Find(ctx, gatewayID)

	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, result.Groups)
}

func TestGroupedFinder_Empty(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		List(mock.Anything, domain.ListFilter{GatewayID: gatewayID, Page: 1, Size: 100}).
		Return([]*domain.Registry{}, 0, nil).
		Once()

	result, err := appregistry.NewGroupedFinder(repo).Find(context.Background(), gatewayID)

	require.NoError(t, err)
	assert.NotNil(t, result.Groups)
	assert.Empty(t, result.Groups)
	assert.Zero(t, result.TotalInstances)
}

func TestGroupedFinder_RepositoryError(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	repositoryError := errors.New("repository unavailable")
	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		List(mock.Anything, domain.ListFilter{GatewayID: gatewayID, Page: 1, Size: 100}).
		Return(nil, 0, repositoryError).
		Once()

	result, err := appregistry.NewGroupedFinder(repo).Find(context.Background(), gatewayID)

	assert.ErrorIs(t, err, repositoryError)
	assert.Empty(t, result.Groups)
}

func groupedRegistry(id string, gatewayID ids.GatewayID, name string, registryType domain.Type, provider string) *domain.Registry {
	registryID := ids.From[ids.RegistryKind](uuid.MustParse(id))
	var llmTarget *domain.LLMTarget
	if provider != "" {
		llmTarget = &domain.LLMTarget{Provider: provider}
	}
	return &domain.Registry{
		ID:        registryID,
		GatewayID: gatewayID,
		Name:      name,
		Type:      registryType,
		LLMTarget: llmTarget,
	}
}

func groupedRegistries(gatewayID ids.GatewayID, offset, count int) []*domain.Registry {
	items := make([]*domain.Registry, 0, count)
	for i := 0; i < count; i++ {
		items = append(items, &domain.Registry{
			ID:        ids.New[ids.RegistryKind](),
			GatewayID: gatewayID,
			Name:      fmt.Sprintf("registry-%03d", offset+i),
			Type:      domain.TypeLLM,
			LLMTarget: &domain.LLMTarget{Provider: "openai"},
		})
	}
	return items
}
