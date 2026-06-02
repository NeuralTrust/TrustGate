package catalog

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/catalog"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/catalog/openrouter"
	"github.com/google/uuid"
)

type fakeRepo struct {
	providers      map[string]domain.Provider
	upsertedModels []domain.Model
	disabledCalls  map[uuid.UUID][]string
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		providers:     make(map[string]domain.Provider),
		disabledCalls: make(map[uuid.UUID][]string),
	}
}

func (f *fakeRepo) UpsertProvider(_ context.Context, p *domain.Provider) error {
	existing, ok := f.providers[p.Code]
	if ok {
		p.ID = existing.ID
	} else {
		p.ID = uuid.New()
	}
	f.providers[p.Code] = *p
	return nil
}

func (f *fakeRepo) UpsertModel(_ context.Context, m *domain.Model) error {
	f.upsertedModels = append(f.upsertedModels, *m)
	return nil
}

func (f *fakeRepo) DisableModelsExcept(_ context.Context, providerID uuid.UUID, source string, keepSlugs []string) error {
	if source != sourceOpenRouter {
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

func TestSyncer_Sync(t *testing.T) {
	t.Parallel()
	const payload = `{
		"data": [
			{"id":"openai/gpt-4o","name":"GPT-4o","context_length":128000,"pricing":{"prompt":"0.0000025","completion":"0.00001"}},
			{"id":"mistralai/mistral-large","name":"Mistral Large","context_length":32000,"pricing":{"prompt":"0.000002","completion":"0.000006"}},
			{"id":"unknownvendor/foo","name":"ignored"}
		]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	repo := newFakeRepo()
	client := openrouter.NewClient(srv.URL, "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewSyncer(repo, client, logger)

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
		t.Fatalf("vertex (no OpenRouter models) keep slugs = %v, want empty", keep)
	}
}

func TestSyncer_Sync_PropagatesClientError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	repo := newFakeRepo()
	client := openrouter.NewClient(srv.URL, "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewSyncer(repo, client, logger)

	if err := s.Sync(context.Background()); err == nil {
		t.Fatal("expected error from failing client")
	}
}
