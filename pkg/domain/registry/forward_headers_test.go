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

package registry

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

func TestNormalizeForwardClientHeaders(t *testing.T) {
	opts := map[string]any{
		"base_url":                         "https://llm.example.com",
		ProviderOptionForwardClientHeaders: []any{" traceparent", "TraceParent", "tracestate", "x-request-id", ""},
	}
	if err := NormalizeForwardClientHeaders(opts); err != nil {
		t.Fatalf("NormalizeForwardClientHeaders: %v", err)
	}
	got, _ := opts[ProviderOptionForwardClientHeaders].([]string)
	want := []string{"Traceparent", "Tracestate", "X-Request-Id"}
	if !slices.Equal(got, want) {
		t.Fatalf("normalized = %v, want %v", got, want)
	}
	if opts["base_url"] != "https://llm.example.com" {
		t.Fatal("other provider options must be left alone")
	}

	empty := map[string]any{ProviderOptionForwardClientHeaders: []any{}}
	if err := NormalizeForwardClientHeaders(empty); err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if _, ok := empty[ProviderOptionForwardClientHeaders]; ok {
		t.Fatal("an empty list must be dropped")
	}

	tooMany := make([]any, maxForwardClientHeaders+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("x-h-%d", i)
	}
	invalid := map[string]any{
		"credential":       []any{"Authorization"},
		"api key":          []any{"x-api-key"},
		"cookie":           []any{"cookie"},
		"framing":          []any{"content-length"},
		"compression":      []any{"accept-encoding"},
		"gateway header":   []any{"X-AG-Trace-Id"},
		"tg header":        []any{"x-tg-anything"},
		"not a token":      []any{"bad header"},
		"not a list":       "traceparent",
		"not strings":      []any{1},
		"too many headers": tooMany,
	}
	for name, value := range invalid {
		err := NormalizeForwardClientHeaders(map[string]any{ProviderOptionForwardClientHeaders: value})
		if !errors.Is(err, ErrInvalidRegistry) {
			t.Errorf("%s: err = %v, want ErrInvalidRegistry", name, err)
		}
	}
}

func TestForwardClientHeadersSkipsWhatCannotBeForwarded(t *testing.T) {
	got := ForwardClientHeaders(map[string]any{ProviderOptionForwardClientHeaders: []any{"traceparent", "authorization", "x-request-id"}})
	if !slices.Equal(got, []string{"Traceparent", "X-Request-Id"}) {
		t.Fatalf("ForwardClientHeaders = %v", got)
	}
	if got := ForwardClientHeaders(nil); got != nil {
		t.Fatalf("no options: %v", got)
	}
}

func TestLLMTargetValidateNormalizesForwardClientHeaders(t *testing.T) {
	target := &LLMTarget{
		Provider:        "openai",
		ProviderOptions: map[string]any{ProviderOptionForwardClientHeaders: []any{"traceparent"}},
		Auth:            &TargetAuth{Type: AuthTypeAPIKey, APIKey: &APIKeyAuth{APIKey: "sk-test"}},
	}
	if err := target.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got, _ := target.ProviderOptions[ProviderOptionForwardClientHeaders].([]string); !slices.Equal(got, []string{"Traceparent"}) {
		t.Fatalf("stored list = %v", got)
	}
	target.ProviderOptions[ProviderOptionForwardClientHeaders] = []any{"authorization"}
	if err := target.Validate(); !errors.Is(err, ErrInvalidRegistry) {
		t.Fatalf("err = %v, want ErrInvalidRegistry", err)
	}
}

func TestForwardClientHeadersRefusesTheUserToken(t *testing.T) {
	opts := map[string]any{ProviderOptionForwardClientHeaders: []any{"x-neuraltrust-user-token"}}
	if err := NormalizeForwardClientHeaders(opts); !errors.Is(err, ErrInvalidRegistry) {
		t.Fatalf("err = %v, want ErrInvalidRegistry", err)
	}
	if got := ForwardClientHeaders(map[string]any{ProviderOptionForwardClientHeaders: []any{"X-NeuralTrust-User-Token", "traceparent"}}); !slices.Equal(got, []string{"Traceparent"}) {
		t.Fatalf("forwarded = %v", got)
	}
}
