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

	t.Run("CheckAllowedModel rejects empty and disallowed models", func(t *testing.T) {
		t.Parallel()
		if err := CheckAllowedModel("gpt-4o", nil); err != nil {
			t.Fatalf("empty allow-list: %v", err)
		}
		if err := CheckAllowedModel("gpt-4o", []string{"gpt-4o"}); err != nil {
			t.Fatalf("allowed: %v", err)
		}
		if err := CheckAllowedModel("", []string{"gpt-4o"}); !errors.Is(err, ErrModelNotAllowed) {
			t.Fatalf("empty model: %v", err)
		}
		if err := CheckAllowedModel("claude-3", []string{"gpt-4o"}); !errors.Is(err, ErrModelNotAllowed) {
			t.Fatalf("disallowed: %v", err)
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

func TestCheckAllowedModel(t *testing.T) {
	t.Parallel()
	if err := CheckAllowedModel("whisper-1", nil); err != nil {
		t.Fatalf("empty allow-list: %v", err)
	}
	if err := CheckAllowedModel("whisper-1", []string{"whisper-1"}); err != nil {
		t.Fatalf("allowed: %v", err)
	}
	if err := CheckAllowedModel("tts-1", []string{"whisper-1"}); !errors.Is(err, ErrModelNotAllowed) {
		t.Fatalf("disallowed: %v", err)
	}
	if err := CheckAllowedModel("", []string{"whisper-1"}); !errors.Is(err, ErrModelNotAllowed) {
		t.Fatalf("missing: %v", err)
	}
}

func TestEnforceModelWildcardAllowList(t *testing.T) {
	t.Parallel()

	t.Run("pattern admits a matching model", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"model":"gpt-4.1"}`)
		out, model, err := EnforceModel(body, []string{"gpt-*"}, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if model != "gpt-4.1" {
			t.Fatalf("model = %q", model)
		}
		if string(out) != string(body) {
			t.Fatalf("body changed: %s", out)
		}
	})

	t.Run("pattern denies a model outside the family", func(t *testing.T) {
		t.Parallel()
		_, _, err := EnforceModel([]byte(`{"model":"claude-3-opus"}`), []string{"gpt-*"}, "")
		if !errors.Is(err, ErrModelNotAllowed) {
			t.Fatalf("expected ErrModelNotAllowed, got %v", err)
		}
	})

	t.Run("a pattern never authorizes itself", func(t *testing.T) {
		t.Parallel()
		_, _, err := EnforceModel([]byte(`{"model":"gpt-*"}`), []string{"gpt-*"}, "")
		if !errors.Is(err, ErrModelNotAllowed) {
			t.Fatalf("expected ErrModelNotAllowed, got %v", err)
		}
		if err := CheckAllowedModel("gpt-*", []string{"gpt-*"}); !errors.Is(err, ErrModelNotAllowed) {
			t.Fatalf("expected ErrModelNotAllowed, got %v", err)
		}
	})

	t.Run("a pattern default is never injected into the body", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"messages":[]}`)
		out, _, err := EnforceModel(body, []string{"gpt-*"}, "gpt-*")
		if !errors.Is(err, ErrModelNotAllowed) {
			t.Fatalf("expected ErrModelNotAllowed, got %v", err)
		}
		if string(out) != string(body) {
			t.Fatalf("body must be left untouched, got %s", out)
		}
	})

	t.Run("a concrete default under a pattern allow-list is injected", func(t *testing.T) {
		t.Parallel()
		out, model, err := EnforceModel([]byte(`{"messages":[]}`), []string{"gpt-*"}, "gpt-4o-mini")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if model != "gpt-4o-mini" {
			t.Fatalf("model = %q", model)
		}
		var probe struct {
			Model string `json:"model"`
		}
		if err := json.Unmarshal(out, &probe); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if probe.Model != "gpt-4o-mini" {
			t.Fatalf("injected model = %q", probe.Model)
		}
	})
}

func TestCheckAllowedModelRejectsPatternWithOpenAllowList(t *testing.T) {
	t.Parallel()
	if err := CheckAllowedModel("gpt-*", nil); !errors.Is(err, ErrModelNotAllowed) {
		t.Fatalf("an open allow-list must still refuse a pattern subject, got %v", err)
	}
	if err := CheckAllowedModel("gpt-4o", nil); err != nil {
		t.Fatalf("an open allow-list must accept a concrete model: %v", err)
	}
}
