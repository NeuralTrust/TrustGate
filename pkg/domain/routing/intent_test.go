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

package routing_test

import (
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/routing"
)

func TestParseModelRef(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		ref     string
		want    routing.Intent
		wantErr error
	}{
		{"empty is zero intent", "", routing.Intent{}, nil},
		{"whitespace is zero intent", "   ", routing.Intent{}, nil},
		{"qualified provider model", "@openai/gpt-5", routing.Intent{Provider: "openai", Model: "gpt-5"}, nil},
		{"provider is lowercased", "@OpenAI/gpt-5", routing.Intent{Provider: "openai", Model: "gpt-5"}, nil},
		{"model keeps nested slashes", "@openrouter/meta-llama/llama-3-70b", routing.Intent{Provider: "openrouter", Model: "meta-llama/llama-3-70b"}, nil},
		{"pool alias", "pool:fast-chat", routing.Intent{PoolAlias: "fast-chat"}, nil},
		{"pool prefix is case insensitive", "POOL:fast-chat", routing.Intent{PoolAlias: "fast-chat"}, nil},
		{"short model", "gpt-5", routing.Intent{Model: "gpt-5"}, nil},
		{"provider/model without @ stays a native model", "openai/gpt-5", routing.Intent{Model: "openai/gpt-5"}, nil},
		{"bedrock arn stays a native model", "arn:aws:bedrock:eu-west-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-4-v1:0",
			routing.Intent{Model: "arn:aws:bedrock:eu-west-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-4-v1:0"}, nil},
		{"empty pool alias", "pool:", routing.Intent{}, routing.ErrInvalidModelRef},
		{"pool alias with slash", "pool:a/b", routing.Intent{}, routing.ErrInvalidModelRef},
		{"@ without slash", "@openai", routing.Intent{}, routing.ErrInvalidModelRef},
		{"@ with empty provider", "@/gpt-5", routing.Intent{}, routing.ErrInvalidModelRef},
		{"@ with empty model", "@openai/", routing.Intent{}, routing.ErrInvalidModelRef},
		{"@ with invalid provider chars", "@open ai/gpt-5", routing.Intent{}, routing.ErrInvalidModelRef},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := routing.ParseModelRef(tc.ref)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected %+v, got %+v", tc.want, got)
			}
		})
	}
}

func TestRoutingIntentPredicates(t *testing.T) {
	t.Parallel()
	if !(routing.Intent{}).IsZero() {
		t.Fatal("empty intent must be zero")
	}
	qualified := routing.Intent{Provider: "openai", Model: "gpt-5"}
	if !qualified.IsQualified() || qualified.IsShortModel() || qualified.IsPool() {
		t.Fatal("qualified intent predicates mismatch")
	}
	short := routing.Intent{Model: "gpt-5"}
	if !short.IsShortModel() || short.IsQualified() {
		t.Fatal("short intent predicates mismatch")
	}
	pool := routing.Intent{PoolAlias: "fast"}
	if !pool.IsPool() || pool.IsZero() {
		t.Fatal("pool intent predicates mismatch")
	}
}
