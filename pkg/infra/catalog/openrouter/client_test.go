package openrouter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_ListModels(t *testing.T) {
	t.Parallel()
	const payload = `{
		"data": [
			{"id":"openai/gpt-4o","name":"OpenAI: GPT-4o","context_length":128000,
			 "pricing":{"prompt":"0.0000025","completion":"0.00001"},
			 "top_provider":{"max_completion_tokens":16384}},
			{"id":"mistralai/mistral-large","name":"Mistral Large","context_length":32000,
			 "pricing":{"prompt":"0.000002","completion":"0.000006"}},
			{"id":"malformed-id","name":"skip me"}
		]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("authorization = %q", got)
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	models, err := client.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels error: %v", err)
	}
	if len(models) != 2 {
		t.Fatalf("expected 2 models (malformed skipped), got %d", len(models))
	}

	first := models[0]
	if first.ProviderCode != "openai" || first.Slug != "gpt-4o" {
		t.Fatalf("unexpected first model: %+v", first)
	}
	if first.ExternalID != "openai/gpt-4o" {
		t.Fatalf("external id = %q", first.ExternalID)
	}
	if first.ContextWindow != 128000 || first.MaxOutput != 16384 {
		t.Fatalf("unexpected window/output: %+v", first)
	}
	if first.InputPrice != "0.0000025" || first.OutputPrice != "0.00001" {
		t.Fatalf("unexpected pricing: %+v", first)
	}
}

func TestClient_ListModels_Non2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "")
	if _, err := client.ListModels(context.Background()); err == nil {
		t.Fatal("expected error on non-2xx response")
	}
}
