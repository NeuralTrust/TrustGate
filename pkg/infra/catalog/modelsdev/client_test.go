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

package modelsdev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_ListModels(t *testing.T) {
	t.Parallel()
	const payload = `{
		"openai": {
			"id": "openai",
			"name": "OpenAI",
			"models": {
				"gpt-4o": {
					"id": "gpt-4o",
					"name": "GPT-4o",
					"limit": {"context": 128000, "output": 16384},
					"cost": {"input": 2.5, "output": 10}
				}
			}
		},
		"anthropic": {
			"id": "anthropic",
			"name": "Anthropic",
			"models": {
				"claude-sonnet-4-5": {
					"id": "claude-sonnet-4-5",
					"name": "Claude Sonnet 4.5",
					"limit": {"context": 200000, "output": 64000},
					"cost": {"input": 3, "output": 15}
				}
			}
		}
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api.json" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	models, err := client.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels error: %v", err)
	}
	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d", len(models))
	}

	// Sorted by provider code then slug: anthropic first.
	anthropic := models[0]
	if anthropic.ProviderCode != "anthropic" || anthropic.Slug != "claude-sonnet-4-5" {
		t.Fatalf("unexpected first model: %+v", anthropic)
	}
	if anthropic.ExternalID != "anthropic/claude-sonnet-4-5" {
		t.Fatalf("external id = %q", anthropic.ExternalID)
	}
	if anthropic.ContextWindow != 200000 || anthropic.MaxOutput != 64000 {
		t.Fatalf("unexpected window/output: %+v", anthropic)
	}
	// 3 USD / 1M tokens -> 0.000003 per token.
	if anthropic.InputPrice != "0.000003" || anthropic.OutputPrice != "0.000015" {
		t.Fatalf("unexpected anthropic pricing: in=%q out=%q", anthropic.InputPrice, anthropic.OutputPrice)
	}

	openai := models[1]
	if openai.ProviderCode != "openai" || openai.Slug != "gpt-4o" {
		t.Fatalf("unexpected second model: %+v", openai)
	}
	if openai.InputPrice != "0.0000025" || openai.OutputPrice != "0.00001" {
		t.Fatalf("unexpected openai pricing: in=%q out=%q", openai.InputPrice, openai.OutputPrice)
	}
}

func TestClient_ListModels_OmitsZeroPrice(t *testing.T) {
	t.Parallel()
	const payload = `{
		"groq": {
			"id": "groq",
			"name": "Groq",
			"models": {
				"openai/gpt-oss-20b": {
					"id": "openai/gpt-oss-20b",
					"name": "GPT-OSS 20B",
					"limit": {"context": 131072, "output": 32768}
				}
			}
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	models, err := client.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels error: %v", err)
	}
	if len(models) != 1 {
		t.Fatalf("expected 1 model, got %d", len(models))
	}
	m := models[0]
	if m.Slug != "openai/gpt-oss-20b" || m.ProviderCode != "groq" {
		t.Fatalf("unexpected model: %+v", m)
	}
	if m.InputPrice != "" || m.OutputPrice != "" {
		t.Fatalf("expected empty pricing for cost-less model, got in=%q out=%q", m.InputPrice, m.OutputPrice)
	}
}

func TestClient_ListModels_DerivesCapabilitiesFromFamily(t *testing.T) {
	t.Parallel()
	const payload = `{
		"openai": {
			"id": "openai",
			"models": {
				"gpt-4.1": {"id":"gpt-4.1","name":"GPT-4.1","family":"gpt"},
				"text-embedding-3-small": {"id":"text-embedding-3-small","name":"text-embedding-3-small","family":"text-embedding"},
				"gpt-image-1.5": {"id":"gpt-image-1.5","name":"gpt-image-1.5","family":"gpt-image"},
				"mystery": {"id":"mystery","name":"Mystery"}
			}
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	models, err := NewClient(srv.URL).ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels error: %v", err)
	}
	got := map[string]map[string]any{}
	for _, m := range models {
		got[m.Slug] = m.Capabilities
	}
	assertCaps := func(slug, key string) {
		t.Helper()
		flags := got[slug]
		if key == "" {
			if flags != nil {
				t.Fatalf("%s capabilities = %v, want unknown", slug, flags)
			}
			return
		}
		if flags[key] != true || len(flags) != 1 {
			t.Fatalf("%s capabilities = %v, want {%s: true}", slug, flags, key)
		}
	}
	assertCaps("gpt-4.1", "chat")
	assertCaps("text-embedding-3-small", "embed")
	assertCaps("gpt-image-1.5", "image")
	assertCaps("mystery", "")
}

func TestCapabilitiesFromFamily(t *testing.T) {
	t.Parallel()
	cases := []struct {
		family string
		key    string
	}{
		{family: "", key: ""},
		{family: "  ", key: ""},
		{family: "gpt", key: "chat"},
		{family: "GPT", key: "chat"},
		{family: "chat", key: "chat"},
		{family: "text-embedding", key: "embed"},
		{family: "cohere-embed", key: "embed"},
		{family: "embed", key: "embed"},
		{family: "gpt-image", key: "image"},
		{family: "imagen", key: "image"},
		{family: "image", key: "image"},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			t.Parallel()
			flags := capabilitiesFromFamily(tc.family)
			if tc.key == "" {
				if flags != nil {
					t.Fatalf("capabilities = %v, want nil", flags)
				}
				return
			}
			if flags[tc.key] != true || len(flags) != 1 {
				t.Fatalf("capabilities = %v, want {%s: true}", flags, tc.key)
			}
		})
	}
}

func TestClient_ListModels_Non2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if _, err := client.ListModels(context.Background()); err == nil {
		t.Fatal("expected error on non-2xx response")
	}
}
