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

package adapter

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestEnforceModel(t *testing.T) {
	t.Parallel()

	t.Run("allowed model passes through unchanged", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"model":"gpt-4o","x":1}`)
		out, model, err := EnforceModel(body, []string{"gpt-4o"}, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if model != "gpt-4o" {
			t.Fatalf("model = %q", model)
		}
		if string(out) != string(body) {
			t.Fatalf("body changed: %s", out)
		}
	})

	t.Run("empty allow-list accepts any model", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"model":"whatever"}`)
		_, model, err := EnforceModel(body, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if model != "whatever" {
			t.Fatalf("model = %q", model)
		}
	})

	t.Run("disallowed model is rejected", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"model":"claude-3"}`)
		_, _, err := EnforceModel(body, []string{"gpt-4o"}, "")
		if !errors.Is(err, ErrModelNotAllowed) {
			t.Fatalf("expected ErrModelNotAllowed, got %v", err)
		}
	})

	t.Run("allow-list enforced when model travels as modelId", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"modelId":"claude-3"}`)
		_, _, err := EnforceModel(body, []string{"gpt-4o"}, "")
		if !errors.Is(err, ErrModelNotAllowed) {
			t.Fatalf("expected ErrModelNotAllowed for disallowed modelId, got %v", err)
		}
		allowed := []byte(`{"modelId":"gpt-4o"}`)
		if _, model, err := EnforceModel(allowed, []string{"gpt-4o"}, ""); err != nil || model != "gpt-4o" {
			t.Fatalf("expected allowed modelId to pass, got model=%q err=%v", model, err)
		}
	})

	t.Run("missing model with allow-list and no default is rejected", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"messages":[]}`)
		_, _, err := EnforceModel(body, []string{"gpt-4o"}, "")
		if !errors.Is(err, ErrModelNotAllowed) {
			t.Fatalf("expected ErrModelNotAllowed when no model and no default, got %v", err)
		}
	})

	t.Run("missing model injects default", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"messages":[]}`)
		out, model, err := EnforceModel(body, []string{"gpt-4o"}, "gpt-4o")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if model != "gpt-4o" {
			t.Fatalf("model = %q", model)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(out, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := decoded["model"]; !ok {
			t.Fatal("default model not injected")
		}
	})

	t.Run("missing model without default passes through", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"messages":[]}`)
		out, model, err := EnforceModel(body, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if model != "" {
			t.Fatalf("model = %q", model)
		}
		if string(out) != string(body) {
			t.Fatalf("body changed: %s", out)
		}
	})
}
