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

package catalog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type listingRepo struct {
	*fakeRepo
	byProvider map[string][]domain.Model
	err        error
	mu         sync.Mutex
	calls      map[string]int
}

func newListingRepo(byProvider map[string][]domain.Model) *listingRepo {
	return &listingRepo{
		fakeRepo:   newFakeRepo(),
		byProvider: byProvider,
		calls:      make(map[string]int),
	}
}

func (r *listingRepo) ListModelsByProviderCode(_ context.Context, providerCode string) ([]domain.Model, error) {
	r.mu.Lock()
	r.calls[providerCode]++
	r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	return r.byProvider[providerCode], nil
}

func (r *listingRepo) callsFor(providerCode string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[providerCode]
}

func newModelAvailability(repo domain.Repository) ModelAvailability {
	mgr := cache.NewTTLMapManager(cache.CatalogAvailabilityCacheTTL)
	mgr.CreateTTLMap(cache.CatalogAvailabilityTTLName, cache.CatalogAvailabilityCacheTTL)
	return NewModelAvailability(repo, mgr, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func enabledModel(slug string) domain.Model {
	return domain.Model{Slug: slug, Enabled: true}
}

func TestModelAvailability_Serves(t *testing.T) {
	t.Parallel()

	listing := map[string][]domain.Model{
		providers.ProviderOpenAI: {enabledModel("gpt-4.1"), enabledModel("gpt-4o-mini")},
		providers.ProviderVertex: {enabledModel("gemini-3-flash-preview")},
		providers.ProviderBedrock: {
			enabledModel("anthropic.claude-sonnet-4"),
			enabledModel("anthropic.claude-opus-4-2026-05-01"),
		},
		providers.ProviderAzure:            {enabledModel("gpt-4.1")},
		providers.ProviderOpenAICompatible: {},
	}

	for _, tc := range []struct {
		name     string
		provider string
		model    string
		want     Verdict
	}{
		{"listed model", providers.ProviderOpenAI, "gpt-4.1", VerdictServes},
		{"model of another provider", providers.ProviderOpenAI, "gemini-3-flash-preview", VerdictAbsent},
		{"listed on its own provider", providers.ProviderVertex, "gemini-3-flash-preview", VerdictServes},
		{"cross-region inference profile", providers.ProviderBedrock, "eu.anthropic.claude-sonnet-4", VerdictServes},
		{"dated deployment suffix", providers.ProviderBedrock, "anthropic.claude-opus-4-2026-05-01", VerdictServes},
		{"unlisted model on a listed provider", providers.ProviderBedrock, "gpt-4.1", VerdictAbsent},
		{"provider with no listing", providers.ProviderCohere, "command-r", VerdictUnknown},
		{"azure deployment names are account specific", providers.ProviderAzure, "my-deployment", VerdictUnknown},
		{"openai compatible endpoints are opaque", providers.ProviderOpenAICompatible, "gpt-4.1", VerdictUnknown},
		{"bedrock arn is an opaque reference", providers.ProviderBedrock, "arn:aws:bedrock:eu-west-1::foundation-model/x", VerdictUnknown},
		{"empty provider", "", "gpt-4.1", VerdictUnknown},
		{"empty model", providers.ProviderOpenAI, "", VerdictUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			availability := newModelAvailability(newListingRepo(listing))
			assert.Equal(t, tc.want, availability.Serves(context.Background(), tc.provider, tc.model))
		})
	}
}

func TestModelAvailability_DisabledModelsAreNotServed(t *testing.T) {
	t.Parallel()
	repo := newListingRepo(map[string][]domain.Model{
		providers.ProviderOpenAI: {enabledModel("gpt-4.1"), {Slug: "gpt-3.5-turbo", Enabled: false}},
	})
	availability := newModelAvailability(repo)

	assert.Equal(t, VerdictAbsent, availability.Serves(context.Background(), providers.ProviderOpenAI, "gpt-3.5-turbo"))
}

func TestModelAvailability_RepositoryErrorIsUnknown(t *testing.T) {
	t.Parallel()
	repo := newListingRepo(nil)
	repo.err = errors.New("snapshot not loaded")
	availability := newModelAvailability(repo)

	assert.Equal(t, VerdictUnknown, availability.Serves(context.Background(), providers.ProviderOpenAI, "gpt-4.1"),
		"a catalog that cannot answer must never be read as a verified absence")
}

func TestModelAvailability_OpenAICompatibleDoesNotInheritOpenAICatalog(t *testing.T) {
	t.Parallel()
	repo := newListingRepo(map[string][]domain.Model{
		providers.ProviderOpenAI: {enabledModel("gpt-4.1")},
	})
	availability := newModelAvailability(repo)

	assert.Equal(t, VerdictUnknown,
		availability.Serves(context.Background(), providers.ProviderOpenAICompatible, "my-private-finetune"),
		"a self-hosted endpoint serves models OpenAI's catalog knows nothing about")
}

func TestModelAvailability_CachesTheProviderListing(t *testing.T) {
	t.Parallel()
	repo := newListingRepo(map[string][]domain.Model{
		providers.ProviderOpenAI: {enabledModel("gpt-4.1")},
	})
	availability := newModelAvailability(repo)

	require.Equal(t, VerdictServes, availability.Serves(context.Background(), providers.ProviderOpenAI, "gpt-4.1"))
	require.Equal(t, VerdictAbsent, availability.Serves(context.Background(), providers.ProviderOpenAI, "gpt-4o"))

	assert.Equal(t, 1, repo.callsFor(providers.ProviderOpenAI),
		"the listing is read once per provider and served from memory afterwards")
}

func TestModelAvailability_ConcurrentCallersShareOneLookup(t *testing.T) {
	t.Parallel()
	repo := newListingRepo(map[string][]domain.Model{
		providers.ProviderVertex: {enabledModel("gemini-3-flash-preview")},
	})
	availability := newModelAvailability(repo)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.Equal(t, VerdictServes,
				availability.Serves(context.Background(), providers.ProviderVertex, "gemini-3-flash-preview"))
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, repo.callsFor(providers.ProviderVertex))
}

func TestModelAvailability_InvalidateCacheRereadsTheListing(t *testing.T) {
	t.Parallel()
	repo := newListingRepo(map[string][]domain.Model{
		providers.ProviderOpenAI: {enabledModel("gpt-4.1")},
	})
	availability := newModelAvailability(repo)

	require.Equal(t, VerdictAbsent, availability.Serves(context.Background(), providers.ProviderOpenAI, "gpt-5"))
	repo.byProvider[providers.ProviderOpenAI] = append(repo.byProvider[providers.ProviderOpenAI], enabledModel("gpt-5"))

	require.Equal(t, VerdictAbsent, availability.Serves(context.Background(), providers.ProviderOpenAI, "gpt-5"))
	availability.InvalidateCache()

	assert.Equal(t, VerdictServes, availability.Serves(context.Background(), providers.ProviderOpenAI, "gpt-5"),
		"a catalog sync must be visible to routing without waiting out the cache TTL")
}
