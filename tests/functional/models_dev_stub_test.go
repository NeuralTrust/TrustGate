//go:build functional

package functional_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

// ModelsDevStub serves the models.dev catalog the gateway syncs at boot, so the
// catalog the suite sees never depends on the live site. The gateway reads it
// through MODELS_DEV_BASE_URL.
var ModelsDevStub *httptest.Server

// modelsDevFixture is the api.json the stub serves. gpt-4 keeps the 8192-token
// window the context preflight test asserts on.
var modelsDevFixture = map[string]any{
	"openai": map[string]any{"models": map[string]any{
		"gpt-4":       modelsDevModel("GPT-4", 8192, 8192),
		"gpt-4o":      modelsDevModel("GPT-4o", 128000, 16384),
		"gpt-4o-mini": modelsDevModel("GPT-4o mini", 128000, 16384),
	}},
	"anthropic": map[string]any{"models": map[string]any{
		"claude-opus-4-5": modelsDevModel("Claude Opus 4.5", 200000, 64000),
	}},
	"google": map[string]any{"models": map[string]any{
		"gemini-3-flash-preview": modelsDevModel("Gemini 3 Flash Preview", 1048576, 65536),
	}},
}

func modelsDevModel(name string, context, output int) map[string]any {
	return map[string]any{
		"name":   name,
		"family": "chat",
		"limit":  map[string]any{"context": context, "output": output},
		"cost":   map[string]any{"input": 1.0, "output": 2.0},
	}
}

// StartModelsDevStub starts the stub once for the suite and returns its base URL.
func StartModelsDevStub() string {
	if ModelsDevStub != nil {
		return ModelsDevStub.URL
	}
	ModelsDevStub = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(modelsDevFixture)
	}))
	return ModelsDevStub.URL
}

// StopModelsDevStub tears the stub down at suite teardown.
func StopModelsDevStub() {
	if ModelsDevStub == nil {
		return
	}
	ModelsDevStub.Close()
	ModelsDevStub = nil
}
