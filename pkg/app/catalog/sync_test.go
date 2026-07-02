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
	s := NewSyncer(repo, client, logger, nil)

	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync error: %v", err)
	}

	if len(repo.providers) != len(seedProviders) {
		t.Fatalf("expected %d providers seeded, got %d", len(seedProviders), len(repo.providers))
	}
	if len(repo.upsertedModels) != 2 {
		t.Fatalf("expected 2 mapped models upserted (unknown vendor skipped), got %d", len(repo.upsertedModels))
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

func TestSyncer_Sync_PropagatesClientError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	repo := newFakeRepo()
	client := modelsdev.NewClient(srv.URL)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewSyncer(repo, client, logger, nil)

	if err := s.Sync(context.Background()); err == nil {
		t.Fatal("expected error from failing client")
	}
}
