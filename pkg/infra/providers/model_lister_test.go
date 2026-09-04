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

package providers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseOpenAIModelList(t *testing.T) {
	t.Parallel()
	body := []byte(`{"object":"list","data":[
		{"id":"gpt-5.6"},
		{"id":"claude-sonnet-5","display_name":"Claude Sonnet 5"},
		{"id":"openrouter/some","name":"Some Model"},
		{"id":"  "},
		{"display_name":"no id"}
	]}`)

	models, err := ParseOpenAIModelList(body)
	if err != nil {
		t.Fatalf("ParseOpenAIModelList() error = %v", err)
	}
	if len(models) != 3 {
		t.Fatalf("ParseOpenAIModelList() len = %d, want 3", len(models))
	}
	if models[0].ID != "gpt-5.6" || models[0].DisplayName != "" {
		t.Fatalf("models[0] = %+v", models[0])
	}
	if models[1].DisplayName != "Claude Sonnet 5" {
		t.Fatalf("models[1] display = %q", models[1].DisplayName)
	}
	if models[2].DisplayName != "Some Model" {
		t.Fatalf("models[2] display = %q, want the name fallback", models[2].DisplayName)
	}
}

func TestParseOpenAIModelList_InvalidJSON(t *testing.T) {
	t.Parallel()
	if _, err := ParseOpenAIModelList([]byte("not json")); !errors.Is(err, ErrModelListingFailed) {
		t.Fatalf("error = %v, want ErrModelListingFailed", err)
	}
}

func TestListBearerModelsGET(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk-test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"m-1"},{"id":"m-2"}]}`))
	}))
	defer srv.Close()

	models, err := ListBearerModelsGET(context.Background(), "test-provider", srv.URL, "sk-test")
	if err != nil {
		t.Fatalf("ListBearerModelsGET() error = %v", err)
	}
	if len(models) != 2 || models[0].ID != "m-1" {
		t.Fatalf("models = %+v", models)
	}
}

func TestListBearerModelsGET_NonOKStatusFails(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	if _, err := ListBearerModelsGET(context.Background(), "test-provider", srv.URL, "sk-test"); !errors.Is(err, ErrModelListingFailed) {
		t.Fatalf("error = %v, want ErrModelListingFailed", err)
	}
}

func TestListBearerModelsGET_MissingKeyFails(t *testing.T) {
	t.Parallel()
	if _, err := ListBearerModelsGET(context.Background(), "test-provider", "http://unused", " "); !errors.Is(err, ErrModelListingFailed) {
		t.Fatalf("error = %v, want ErrModelListingFailed", err)
	}
}
