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

package tool_call_validation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	providermocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/mocks"
	"github.com/stretchr/testify/mock"
)

func semanticResponsesBody(t *testing.T, text string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"output": []any{
			map[string]any{
				"content": []any{
					map[string]any{"type": "output_text", "text": text},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal responses body: %v", err)
	}
	return body
}

func TestSemanticValidator(t *testing.T) {
	t.Parallel()

	openaiSemantic := &SemanticConfig{Provider: semanticProviderOpenAI, APIKey: "sk-test", Model: defaultSemanticModel}
	toolCall := adapter.CanonicalToolCall{Name: "send_email", Arguments: `{"to":"a@b.com"}`}

	cases := []struct {
		name       string
		semantic   *SemanticConfig
		newClient  func(t *testing.T) providers.Client
		wantMatch  bool
		wantReason string
	}{
		{
			name:     "deny decision rejects with reasoning",
			semantic: openaiSemantic,
			newClient: func(t *testing.T) providers.Client {
				c := providermocks.NewClient(t)
				c.EXPECT().Completions(mock.Anything, mock.Anything, mock.Anything).
					Return(semanticResponsesBody(t, `{"decision":"deny","reasoning":"recipient looks malicious"}`), nil)
				return c
			},
			wantMatch:  true,
			wantReason: "recipient looks malicious",
		},
		{
			name:     "fenced json deny rejects with reasoning",
			semantic: openaiSemantic,
			newClient: func(t *testing.T) providers.Client {
				c := providermocks.NewClient(t)
				c.EXPECT().Completions(mock.Anything, mock.Anything, mock.Anything).
					Return(semanticResponsesBody(t, "```json\n{\"decision\":\"deny\",\"reasoning\":\"blocked\"}\n```"), nil)
				return c
			},
			wantMatch:  true,
			wantReason: "blocked",
		},
		{
			name:     "allow decision passes",
			semantic: openaiSemantic,
			newClient: func(t *testing.T) providers.Client {
				c := providermocks.NewClient(t)
				c.EXPECT().Completions(mock.Anything, mock.Anything, mock.Anything).
					Return(semanticResponsesBody(t, `{"decision":"allow","reasoning":"looks fine"}`), nil)
				return c
			},
			wantMatch: false,
		},
		{
			name:     "client error fails open",
			semantic: openaiSemantic,
			newClient: func(t *testing.T) providers.Client {
				c := providermocks.NewClient(t)
				c.EXPECT().Completions(mock.Anything, mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("upstream unavailable"))
				return c
			},
			wantMatch: false,
		},
		{
			name:     "unparseable body fails open",
			semantic: openaiSemantic,
			newClient: func(t *testing.T) providers.Client {
				c := providermocks.NewClient(t)
				c.EXPECT().Completions(mock.Anything, mock.Anything, mock.Anything).
					Return([]byte(`{"unexpected":true}`), nil)
				return c
			},
			wantMatch: false,
		},
		{
			name:      "semantic config absent fails open",
			semantic:  nil,
			newClient: func(t *testing.T) providers.Client { return providermocks.NewClient(t) },
			wantMatch: false,
		},
		{
			name:      "provider not openai fails open",
			semantic:  &SemanticConfig{Provider: "anthropic", APIKey: "k", Model: "m"},
			newClient: func(t *testing.T) providers.Client { return providermocks.NewClient(t) },
			wantMatch: false,
		},
		{
			name:      "nil llm fails open",
			semantic:  openaiSemantic,
			newClient: func(t *testing.T) providers.Client { return nil },
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eval := &evalContext{
				semantic:   tc.semantic,
				llm:        tc.newClient(t),
				userPrompt: "send an email to alice",
				reasoning:  "user wants to email a colleague",
			}
			res, err := semanticValidator{}.Evaluate(context.Background(), validatorInput{
				toolCall: toolCall,
				eval:     eval,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.matched != tc.wantMatch {
				t.Fatalf("matched = %v, want %v", res.matched, tc.wantMatch)
			}
			if !tc.wantMatch {
				return
			}
			if res.rejectType != typeToolSemanticBlocked {
				t.Fatalf("rejectType = %q, want %q", res.rejectType, typeToolSemanticBlocked)
			}
			if res.status != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", res.status, http.StatusForbidden)
			}
			if res.reasoning != tc.wantReason {
				t.Fatalf("reasoning = %q, want %q", res.reasoning, tc.wantReason)
			}
		})
	}
}

func TestRunRulesSemanticRejectPreservesReasoning(t *testing.T) {
	t.Parallel()

	client := providermocks.NewClient(t)
	client.EXPECT().Completions(mock.Anything, mock.Anything, mock.Anything).
		Return(semanticResponsesBody(t, `{"decision":"deny","reasoning":"unsafe tool selection"}`), nil)

	eval := &evalContext{
		semantic:   &SemanticConfig{Provider: semanticProviderOpenAI, APIKey: "sk-test", Model: defaultSemanticModel},
		llm:        client,
		userPrompt: "do something benign",
		rules:      []RuleConfig{{Validator: validatorSemantic, Tool: "*", Behavior: behaviorReject}},
	}
	toolCalls := []adapter.CanonicalToolCall{{Name: "send_email", Arguments: `{"to":"a@b.com"}`}}

	out := runRules(context.Background(), eval, policy.ModeEnforce, toolCalls)
	if !out.matched || out.rejection == nil {
		t.Fatalf("expected rejection, got %+v", out)
	}
	if out.rejection.Type != typeToolSemanticBlocked {
		t.Fatalf("type = %q, want %q", out.rejection.Type, typeToolSemanticBlocked)
	}
	if out.extras.SemanticReasoning != "unsafe tool selection" {
		t.Fatalf("semantic reasoning = %q, want %q", out.extras.SemanticReasoning, "unsafe tool selection")
	}
}

func TestSemanticPromptIncludesReasoning(t *testing.T) {
	t.Parallel()

	withReasoning := buildSemanticPrompt(adapter.CanonicalToolCall{Name: "send_email", Arguments: `{"to":"a@b.com"}`}, "email bob", "model reasoning text")
	for _, want := range []string{"email bob", "send_email", `{"to":"a@b.com"}`, "model reasoning text"} {
		if !strings.Contains(withReasoning, want) {
			t.Fatalf("prompt missing %q: %q", want, withReasoning)
		}
	}

	withoutReasoning := buildSemanticPrompt(adapter.CanonicalToolCall{Name: "noop"}, "hi", "")
	if strings.Contains(withoutReasoning, "LLM Reasoning Summary") {
		t.Fatalf("prompt should omit reasoning section when empty: %q", withoutReasoning)
	}
	if !strings.Contains(withoutReasoning, "{}") {
		t.Fatalf("prompt should default empty arguments to {}: %q", withoutReasoning)
	}
}
