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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/catalog/modelsdev"
)

type fakeRepo struct {
	providers      map[string]domain.Provider
	upsertedModels []domain.Model
	disabledCalls  map[ids.ProviderID][]string
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		providers:     make(map[string]domain.Provider),
		disabledCalls: make(map[ids.ProviderID][]string),
	}
}

func (f *fakeRepo) UpsertProvider(_ context.Context, p *domain.Provider) error {
	existing, ok := f.providers[p.Code]
	if ok {
		p.ID = existing.ID
	} else {
		p.ID = ids.New[ids.ProviderKind]()
	}
	f.providers[p.Code] = *p
	return nil
}

func (f *fakeRepo) UpsertModel(_ context.Context, m *domain.Model) error {
	f.upsertedModels = append(f.upsertedModels, *m)
	return nil
}

func (f *fakeRepo) DisableModelsExcept(_ context.Context, providerID ids.ProviderID, source string, keepSlugs []string) error {
	if source != sourceModelsDev {
		panic("unexpected source: " + source)
	}
	f.disabledCalls[providerID] = keepSlugs
	return nil
}

func (f *fakeRepo) ListProviders(_ context.Context) ([]domain.Provider, error) {
	out := make([]domain.Provider, 0, len(f.providers))
	for _, p := range f.providers {
		out = append(out, p)
	}
	return out, nil
}

func (f *fakeRepo) ListModelsByProviderCode(_ context.Context, _ string) ([]domain.Model, error) {
	return nil, nil
}

func (f *fakeRepo) FindModel(_ context.Context, _ string, _ string) (*domain.Model, error) {
	return nil, commonerrors.ErrNotFound
}

func TestSyncer_Sync(t *testing.T) {
	t.Parallel()
	const payload = `{
		"openai": {
			"id": "openai",
			"name": "OpenAI",
			"models": {
				"gpt-4o": {"id":"gpt-4o","name":"GPT-4o","limit":{"context":128000,"output":16384},"cost":{"input":2.5,"output":10}}
			}
		},
		"mistral": {
			"id": "mistral",
			"name": "Mistral",
			"models": {
				"mistral-large-2411": {"id":"mistral-large-2411","name":"Mistral Large","limit":{"context":131072,"output":8192},"cost":{"input":2,"output":6}}
			}
		},
		"unknownvendor": {
			"id": "unknownvendor",
			"name": "Ignored",
			"models": {
				"foo": {"id":"foo","name":"ignored"}
			}
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	repo := newFakeRepo()
	client := modelsdev.NewClient(srv.URL)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewSyncer(repo, client, logger, nil, nil)

	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync error: %v", err)
	}

	if len(repo.providers) != len(seedProviders) {
		t.Fatalf("expected %d providers seeded, got %d", len(seedProviders), len(repo.providers))
	}
	if len(repo.upsertedModels) != 2+len(cohereSeedModels) {
		t.Fatalf("expected %d mapped models upserted (unknown vendor skipped), got %d", 2+len(cohereSeedModels), len(repo.upsertedModels))
	}
	for _, m := range repo.upsertedModels {
		if !m.Enabled {
			t.Fatalf("model %q should be enabled", m.Slug)
		}
	}
	if len(repo.disabledCalls) != len(seedProviders) {
		t.Fatalf("expected DisableModelsExcept for every seeded provider (%d), got %d", len(seedProviders), len(repo.disabledCalls))
	}
	openaiID := repo.providers["openai"].ID
	if keep := repo.disabledCalls[openaiID]; len(keep) != 1 || keep[0] != "gpt-4o" {
		t.Fatalf("openai keep slugs = %v, want [gpt-4o]", keep)
	}
	vertexID := repo.providers["vertex"].ID
	if keep := repo.disabledCalls[vertexID]; len(keep) != 0 {
		t.Fatalf("vertex (no models.dev models) keep slugs = %v, want empty", keep)
	}
}

// Bedrock lists some models twice: once under the InvokeModel ID and once
// behind an alternative OpenAI-compatible endpoint the Bedrock client cannot
// reach. Only the invocable one belongs in the catalog — while the same marker
// on other providers (Claude on Vertex) must be kept.
func TestSyncer_Sync_SkipsBedrockModelsOnAlternativeEndpoints(t *testing.T) {
	t.Parallel()
	const payload = `{
		"amazon-bedrock": {
			"id": "amazon-bedrock",
			"name": "Amazon Bedrock",
			"models": {
				"openai.gpt-oss-20b-1:0": {"id":"openai.gpt-oss-20b-1:0","name":"gpt-oss-20b"},
				"openai.gpt-oss-20b": {
					"id":"openai.gpt-oss-20b","name":"gpt-oss-20b",
					"provider":{"api":"https://bedrock-mantle.${AWS_REGION}.api.aws/v1"}
				}
			}
		},
		"google-vertex": {
			"id": "google-vertex",
			"name": "Vertex",
			"models": {
				"claude-sonnet-4-5@20250929": {
					"id":"claude-sonnet-4-5@20250929","name":"Claude Sonnet 4.5",
					"provider":{"npm":"@ai-sdk/google-vertex/anthropic"}
				}
			}
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	repo := newFakeRepo()
	s := NewSyncer(repo, modelsdev.NewClient(srv.URL), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync error: %v", err)
	}

	bedrockID := repo.providers["bedrock"].ID
	if keep := repo.disabledCalls[bedrockID]; len(keep) != 1 || keep[0] != "openai.gpt-oss-20b-1:0" {
		t.Fatalf("bedrock keep slugs = %v, want [openai.gpt-oss-20b-1:0]", keep)
	}
	vertexID := repo.providers["vertex"].ID
	if keep := repo.disabledCalls[vertexID]; len(keep) != 1 || keep[0] != "claude-sonnet-4-5@20250929" {
		t.Fatalf("vertex keep slugs = %v, want [claude-sonnet-4-5@20250929]", keep)
	}
}

// Only the global inference profile is offered, so the geography-scoped
// duplicates of a model (us., eu., jp., au.) never reach the catalog — not even
// for clients that list models without scoping the request to a registry.
func TestSyncer_Sync_SkipsGeographyScopedBedrockProfiles(t *testing.T) {
	t.Parallel()
	const payload = `{
		"amazon-bedrock": {
			"id": "amazon-bedrock",
			"name": "Amazon Bedrock",
			"models": {
				"anthropic.claude-opus-5": {"id":"anthropic.claude-opus-5","name":"Claude Opus 5"},
				"global.anthropic.claude-opus-5": {"id":"global.anthropic.claude-opus-5","name":"Claude Opus 5 (Global)"},
				"us.anthropic.claude-opus-5": {"id":"us.anthropic.claude-opus-5","name":"Claude Opus 5 (US)"},
				"eu.anthropic.claude-opus-5": {"id":"eu.anthropic.claude-opus-5","name":"Claude Opus 5 (EU)"},
				"jp.anthropic.claude-opus-5": {"id":"jp.anthropic.claude-opus-5","name":"Claude Opus 5 (JP)"},
				"au.anthropic.claude-opus-5": {"id":"au.anthropic.claude-opus-5","name":"Claude Opus 5 (AU)"},
				"amazon.nova-pro-v1:0": {"id":"amazon.nova-pro-v1:0","name":"Nova Pro"}
			}
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	repo := newFakeRepo()
	s := NewSyncer(repo, modelsdev.NewClient(srv.URL), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync error: %v", err)
	}

	got := map[string]bool{}
	for _, slug := range repo.disabledCalls[repo.providers["bedrock"].ID] {
		got[slug] = true
	}
	want := []string{"anthropic.claude-opus-5", "global.anthropic.claude-opus-5", "amazon.nova-pro-v1:0"}
	if len(got) != len(want) {
		t.Fatalf("bedrock keep slugs = %v, want exactly %v", got, want)
	}
	for _, slug := range want {
		if !got[slug] {
			t.Fatalf("bedrock keep slugs = %v, missing %q", got, slug)
		}
	}
}

func TestSyncer_Sync_PropagatesClientError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	repo := newFakeRepo()
	client := modelsdev.NewClient(srv.URL)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewSyncer(repo, client, logger, nil, nil)

	if err := s.Sync(context.Background()); err == nil {
		t.Fatal("expected error from failing client")
	}
}

type pricingCacheSpy struct {
	invalidations int
}

func (p *pricingCacheSpy) Resolve(context.Context, string, string) Pricing { return Pricing{} }

func (p *pricingCacheSpy) InvalidateCache() { p.invalidations++ }

func TestSyncer_Sync_InvalidatesPricingCache(t *testing.T) {
	t.Parallel()
	const payload = `{"openai":{"id":"openai","name":"OpenAI","models":{"gpt-4o":{"id":"gpt-4o","name":"GPT-4o"}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	pricing := &pricingCacheSpy{}
	s := NewSyncer(newFakeRepo(), modelsdev.NewClient(srv.URL), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, pricing)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync error: %v", err)
	}
	if pricing.invalidations != 1 {
		t.Fatalf("InvalidateCache calls = %d, want 1", pricing.invalidations)
	}
}

// models.dev publishes cache_read and cache_write per model, and the resolver
// reads an empty rate as "bills at the plain input rate". So a rate the sync
// drops does not fail loudly — it silently charges cached tokens at up to ten
// times what the provider charges. This is the assertion that catches that.
func TestSyncer_Sync_CarriesCacheRatesThrough(t *testing.T) {
	t.Parallel()
	const payload = `{
		"anthropic": {
			"id": "anthropic",
			"name": "Anthropic",
			"models": {
				"claude-sonnet-4-5": {"id":"claude-sonnet-4-5","name":"Sonnet",
					"limit":{"context":200000,"output":64000},
					"cost":{"input":3,"output":15,"cache_read":0.3,"cache_write":3.75}}
			}
		},
		"openai": {
			"id": "openai",
			"name": "OpenAI",
			"models": {
				"gpt-4o": {"id":"gpt-4o","name":"GPT-4o","limit":{"context":128000,"output":16384},
					"cost":{"input":2.5,"output":10,"cache_read":1.25}}
			}
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	repo := newFakeRepo()
	s := NewSyncer(repo, modelsdev.NewClient(srv.URL),
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync error: %v", err)
	}

	got := map[string]domain.Model{}
	for _, m := range repo.upsertedModels {
		got[m.Slug] = m
	}

	sonnet, ok := got["claude-sonnet-4-5"]
	if !ok {
		t.Fatal("claude-sonnet-4-5 was not upserted")
	}
	if sonnet.CacheReadPrice == "" || sonnet.CacheWritePrice == "" {
		t.Fatalf("cache rates dropped in sync: read=%q write=%q",
			sonnet.CacheReadPrice, sonnet.CacheWritePrice)
	}
	// models.dev quotes per million; the catalog stores per token.
	if want := "0.0000003"; sonnet.CacheReadPrice != want {
		t.Fatalf("cache_read = %q, want %q", sonnet.CacheReadPrice, want)
	}
	if want := "0.00000375"; sonnet.CacheWritePrice != want {
		t.Fatalf("cache_write = %q, want %q", sonnet.CacheWritePrice, want)
	}

	// A model that publishes cache_read but no cache_write keeps the write rate
	// empty, which the resolver reads as the plain input rate.
	gpt, ok := got["gpt-4o"]
	if !ok {
		t.Fatal("gpt-4o was not upserted")
	}
	if want := "0.00000125"; gpt.CacheReadPrice != want {
		t.Fatalf("gpt-4o cache_read = %q, want %q", gpt.CacheReadPrice, want)
	}
	if gpt.CacheWritePrice != "" {
		t.Fatalf("gpt-4o cache_write = %q, want empty (unpublished)", gpt.CacheWritePrice)
	}
}
