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

package catalog_test

import (
	"context"
	"errors"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	regmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	factorymocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type stubModelLister struct {
	models []providers.LiveModel
	err    error
	calls  int
}

func (s *stubModelLister) ListLiveModels(context.Context, *providers.Config) ([]providers.LiveModel, error) {
	s.calls++
	return s.models, s.err
}

func openaiRegistry(auth *registrydomain.TargetAuth) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](),
		LLMTarget: &registrydomain.LLMTarget{
			Provider: providers.ProviderOpenAI,
			Auth:     auth,
		},
	}
}

func apiKeyAuth(key string) *registrydomain.TargetAuth {
	return &registrydomain.TargetAuth{
		Type:   registrydomain.AuthTypeAPIKey,
		APIKey: &registrydomain.APIKeyAuth{APIKey: key},
	}
}

func liveIDs(ids ...string) []providers.LiveModel {
	out := make([]providers.LiveModel, 0, len(ids))
	for _, id := range ids {
		out = append(out, providers.LiveModel{ID: id})
	}
	return out
}

func TestLiveAvailabilityFilter_NarrowsToLiveModels(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := factorymocks.NewProviderLocator(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	lister := &stubModelLister{models: liveIDs("GPT-5.6", "gpt-4o-mini")}

	locator.EXPECT().GetModelLister(providers.ProviderOpenAI).Return(lister, nil)
	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(openaiRegistry(apiKeyAuth("sk-restricted")), nil).Once()

	filter := appcatalog.NewLiveAvailabilityFilter(finder, locator, discardLogger())
	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderOpenAI,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
		Models: []catalogdomain.Model{
			{Slug: "gpt-5.6"},
			{Slug: "gpt-4o-mini"},
			{Slug: "o4", ExternalID: "o4-preview"},
		},
	})

	// Case-insensitive match on slug; the model the key cannot use is dropped.
	assert.Equal(t, []string{"gpt-5.6", "gpt-4o-mini"}, slugsOf(got))
}

func TestLiveAvailabilityFilter_MatchesExternalID(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := factorymocks.NewProviderLocator(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	lister := &stubModelLister{models: liveIDs("o4-preview")}

	locator.EXPECT().GetModelLister(providers.ProviderOpenAI).Return(lister, nil)
	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(openaiRegistry(apiKeyAuth("sk-restricted")), nil).Once()

	filter := appcatalog.NewLiveAvailabilityFilter(finder, locator, discardLogger())
	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderOpenAI,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
		Models: []catalogdomain.Model{
			{Slug: "o4", ExternalID: "o4-preview"},
			{Slug: "gpt-4o"},
		},
	})

	assert.Equal(t, []string{"o4"}, slugsOf(got))
}

func TestLiveAvailabilityFilter_FallsBackWhenListingFails(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := factorymocks.NewProviderLocator(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	lister := &stubModelLister{err: errors.New("provider down")}

	locator.EXPECT().GetModelLister(providers.ProviderOpenAI).Return(lister, nil)
	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(openaiRegistry(apiKeyAuth("sk-any")), nil).Once()

	filter := appcatalog.NewLiveAvailabilityFilter(finder, locator, discardLogger())
	models := catalogModels("gpt-5.6", "gpt-4o")
	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderOpenAI,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
		Models:       models,
	})

	assert.Equal(t, slugsOf(models), slugsOf(got))
}

func TestLiveAvailabilityFilter_FallsBackOnEmptyIntersection(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := factorymocks.NewProviderLocator(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	lister := &stubModelLister{models: liveIDs("ft:gpt-4o:custom")}

	locator.EXPECT().GetModelLister(providers.ProviderOpenAI).Return(lister, nil)
	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(openaiRegistry(apiKeyAuth("sk-any")), nil).Once()

	filter := appcatalog.NewLiveAvailabilityFilter(finder, locator, discardLogger())
	models := catalogModels("gpt-5.6", "gpt-4o")
	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderOpenAI,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
		Models:       models,
	})

	// A naming mismatch must not empty the picker.
	assert.Equal(t, slugsOf(models), slugsOf(got))
}

func TestLiveAvailabilityFilter_LeavesBedrockToServerlessFilter(t *testing.T) {
	t.Parallel()
	filter := appcatalog.NewLiveAvailabilityFilter(
		regmocks.NewFinder(t),
		factorymocks.NewProviderLocator(t),
		discardLogger(),
	)
	models := catalogModels("amazon.nova-pro-v1:0")
	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderBedrock,
		GatewayID:    ids.New[ids.GatewayKind](),
		RegistryID:   ids.New[ids.RegistryKind](),
		Models:       models,
	})
	assert.Equal(t, slugsOf(models), slugsOf(got))
}

func TestLiveAvailabilityFilter_SkipsProvidersWithoutLister(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().GetModelLister("vertex").Return(nil, errors.New("unsupported")).Once()

	filter := appcatalog.NewLiveAvailabilityFilter(finder, locator, discardLogger())
	models := catalogModels("gemini-2.5-pro")
	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: "vertex",
		GatewayID:    ids.New[ids.GatewayKind](),
		RegistryID:   ids.New[ids.RegistryKind](),
		Models:       models,
	})
	assert.Equal(t, slugsOf(models), slugsOf(got))
}

func TestLiveAvailabilityFilter_CachesLiveListingPerCredentials(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := factorymocks.NewProviderLocator(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	lister := &stubModelLister{models: liveIDs("gpt-5.6")}
	registry := openaiRegistry(apiKeyAuth("sk-stable"))

	locator.EXPECT().GetModelLister(providers.ProviderOpenAI).Return(lister, nil)
	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).Return(registry, nil).Twice()

	filter := appcatalog.NewLiveAvailabilityFilter(finder, locator, discardLogger())
	in := appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderOpenAI,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
		Models:       catalogModels("gpt-5.6", "gpt-4o"),
	}

	first := filter.Filter(context.Background(), in)
	second := filter.Filter(context.Background(), in)

	assert.Equal(t, []string{"gpt-5.6"}, slugsOf(first))
	assert.Equal(t, []string{"gpt-5.6"}, slugsOf(second))
	assert.Equal(t, 1, lister.calls, "second render must reuse the cached provider listing")
}
