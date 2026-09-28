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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type stubLiveModelSource struct {
	models      []appcatalog.LiveModel
	err         error
	unsupported bool
	calls       int
}

func (s *stubLiveModelSource) Supports(string) bool { return !s.unsupported }

func (s *stubLiveModelSource) List(context.Context, string, *registrydomain.TargetAuth, map[string]any) ([]appcatalog.LiveModel, error) {
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

func liveIDs(ids ...string) []appcatalog.LiveModel {
	out := make([]appcatalog.LiveModel, 0, len(ids))
	for _, id := range ids {
		out = append(out, appcatalog.LiveModel{ID: id})
	}
	return out
}

func TestLiveAvailabilityFilter_NarrowsToLiveModels(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	source := &stubLiveModelSource{models: liveIDs("GPT-5.6", "gpt-4o-mini")}

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(openaiRegistry(apiKeyAuth("sk-restricted")), nil).Once()

	filter := appcatalog.NewLiveAvailabilityFilter(finder, source, discardLogger())
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
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	source := &stubLiveModelSource{models: liveIDs("o4-preview")}

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(openaiRegistry(apiKeyAuth("sk-restricted")), nil).Once()

	filter := appcatalog.NewLiveAvailabilityFilter(finder, source, discardLogger())
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
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	source := &stubLiveModelSource{err: errors.New("provider down")}

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(openaiRegistry(apiKeyAuth("sk-any")), nil).Once()

	filter := appcatalog.NewLiveAvailabilityFilter(finder, source, discardLogger())
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
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	source := &stubLiveModelSource{models: liveIDs("ft:gpt-4o:custom")}

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(openaiRegistry(apiKeyAuth("sk-any")), nil).Once()

	filter := appcatalog.NewLiveAvailabilityFilter(finder, source, discardLogger())
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
		&stubLiveModelSource{},
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
	source := &stubLiveModelSource{unsupported: true, err: errors.New("unsupported")}

	filter := appcatalog.NewLiveAvailabilityFilter(finder, source, discardLogger())
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
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	source := &stubLiveModelSource{models: liveIDs("gpt-5.6")}
	registry := openaiRegistry(apiKeyAuth("sk-stable"))

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).Return(registry, nil).Twice()

	filter := appcatalog.NewLiveAvailabilityFilter(finder, source, discardLogger())
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
	assert.Equal(t, 1, source.calls, "second render must reuse the cached provider listing")
}

func compatibleRegistry(auth *registrydomain.TargetAuth) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](),
		LLMTarget: &registrydomain.LLMTarget{
			Provider: providers.ProviderOpenAICompatible,
			Auth:     auth,
		},
	}
}

// A self-hosted endpoint has no catalog rows by design, so narrowing had
// nothing to narrow and the picker was handed an empty list for a registry
// whose connection test had just listed its models (RUN-1552).
func TestLiveCatalog_ListsARegistryTheCatalogDoesNotCarry(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	source := &stubLiveModelSource{
		models: []appcatalog.LiveModel{
			{ID: "my-private-finetune", DisplayName: "My private finetune"},
			{ID: "llama-3.1-70b"},
		},
	}

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(compatibleRegistry(apiKeyAuth("sk-local")), nil).Once()

	_, lister := appcatalog.NewLiveCatalog(finder, source, discardLogger())
	got := lister.List(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderOpenAICompatible,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
	})

	assert.Len(t, got, 2)
	assert.Equal(t, "my-private-finetune", got[0].Slug)
	assert.Equal(t, "my-private-finetune", got[0].ExternalID)
	assert.Equal(t, "My private finetune", got[0].DisplayName)
	assert.True(t, got[0].Enabled)
	// A model with no name of its own is still selectable under its id.
	assert.Equal(t, "llama-3.1-70b", got[1].DisplayName)
}

func TestLiveCatalog_NeverWidensACatalogThatAnswered(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	source := &stubLiveModelSource{models: liveIDs("gpt-4o-mini", "gpt-5.6")}

	_, lister := appcatalog.NewLiveCatalog(finder, source, discardLogger())
	got := lister.List(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderOpenAI,
		GatewayID:    ids.New[ids.GatewayKind](),
		RegistryID:   ids.New[ids.RegistryKind](),
		Models:       []catalogdomain.Model{{Slug: "gpt-4o-mini"}},
	})

	assert.Nil(t, got, "narrowing owns a catalog that has rows; listing only answers when it has none")
	assert.Zero(t, source.calls, "the provider must not be called to answer a question the catalog answered")
}

func TestLiveCatalog_StaysSilentWithoutARegistryToAsk(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	source := &stubLiveModelSource{models: liveIDs("whatever")}

	_, lister := appcatalog.NewLiveCatalog(finder, source, discardLogger())

	assert.Nil(t, lister.List(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderOpenAICompatible,
	}), "an unscoped listing has no credentials to list against")
}

func TestLiveCatalog_LeavesBedrockAlone(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	source := &stubLiveModelSource{models: liveIDs("anthropic.claude")}

	_, lister := appcatalog.NewLiveCatalog(finder, source, discardLogger())
	got := lister.List(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderBedrock,
		GatewayID:    ids.New[ids.GatewayKind](),
		RegistryID:   ids.New[ids.RegistryKind](),
	})

	assert.Nil(t, got, "Bedrock is listed through the AWS control plane, not this path")
	assert.Zero(t, source.calls)
}

func TestLiveCatalog_ReportsNothingWhenTheProviderCannotBeAsked(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	source := &stubLiveModelSource{err: errors.New("connection refused")}

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(compatibleRegistry(apiKeyAuth("sk-local")), nil).Once()

	_, lister := appcatalog.NewLiveCatalog(finder, source, discardLogger())
	got := lister.List(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderOpenAICompatible,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
	})

	assert.Nil(t, got, "an unreachable endpoint leaves the empty catalog as it was")
}
