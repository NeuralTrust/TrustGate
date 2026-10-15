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

package strategies

import (
	"context"
	"fmt"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestSR1InputNativeFormatsAndTurnIdentity(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		input   string
		turn    string
		newUser bool
		invalid bool
	}{
		{
			name:  "Bedrock text blocks",
			body:  `{"system":[{"text":"system instruction"}],"messages":[{"role":"user","content":[{"text":"old"}]},{"role":"assistant","content":[{"text":"answer"}]},{"role":"user","content":[{"text":"hard"},{"text":"question"}]}]}`,
			input: "hard\nquestion", turn: "2:hard\nquestion", newUser: true,
		},
		{
			name:  "Bedrock assistant prefill",
			body:  `{"messages":[{"role":"user","content":[{"text":"hard"}]},{"role":"assistant","content":[{"text":"Here is"}]}]}`,
			input: "hard", turn: "0:hard", newUser: true,
		},
		{
			name:  "Bedrock tool call continuation",
			body:  `{"messages":[{"role":"user","content":[{"text":"hard"}]},{"role":"assistant","content":[{"toolUse":{"toolUseId":"a","name":"f","input":{}}}]}]}`,
			input: "hard", turn: "0:hard",
		},
		{
			name:  "Bedrock tool result continuation",
			body:  `{"messages":[{"role":"user","content":[{"text":"hard"}]},{"role":"assistant","content":[{"toolUse":{"toolUseId":"a","name":"f","input":{}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"a","content":[{"text":"result"}]}}]}]}`,
			input: "hard", turn: "0:hard",
		},
		{
			name: "Bedrock tool result without history",
			body: `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"a","content":[{"text":"result"}]}}]}]}`,
			turn: "continuation",
		},
		{
			name:  "Gemini latest user text",
			body:  `{"systemInstruction":{"parts":[{"text":"system instruction"}]},"contents":[{"role":"user","parts":[{"text":"old"}]},{"role":"model","parts":[{"text":"answer"}]},{"role":"user","parts":[{"text":"hard"},{"text":"question"}]}]}`,
			input: "hard\nquestion", turn: "2:hard\nquestion", newUser: true,
		},
		{
			name:  "Gemini omitted user role",
			body:  `{"contents":[{"parts":[{"text":"hi"}]}]}`,
			input: "hi", turn: "0:hi", newUser: true,
		},
		{
			name:  "Gemini model prefill",
			body:  `{"contents":[{"role":"user","parts":[{"text":"hard"}]},{"role":"model","parts":[{"text":"Here is"}]}]}`,
			input: "hard", turn: "0:hard", newUser: true,
		},
		{
			name:  "Gemini function call continuation",
			body:  `{"contents":[{"role":"user","parts":[{"text":"hard"}]},{"role":"model","parts":[{"functionCall":{"name":"f","args":{}}}]}]}`,
			input: "hard", turn: "0:hard",
		},
		{
			name:  "Gemini function response continuation",
			body:  `{"contents":[{"role":"user","parts":[{"text":"hard"}]},{"role":"model","parts":[{"functionCall":{"name":"f","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"name":"f","response":{"result":"done"}}}]}]}`,
			input: "hard", turn: "0:hard",
		},
		{
			name:  "Gemini snake function continuation",
			body:  `{"contents":[{"role":"user","parts":[{"text":"hard"}]},{"role":"model","parts":[{"function_call":{"name":"f","args":{}}}]},{"role":"user","parts":[{"function_response":{"name":"f","response":{"result":"done"}}}]}]}`,
			input: "hard", turn: "0:hard",
		},
		{
			name: "Gemini function response without history",
			body: `{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"f","response":{"result":"done"}}}]}]}`,
			turn: "continuation",
		},
		{
			name:    "textless new turn does not reuse old user text",
			body:    `{"contents":[{"role":"user","parts":[{"text":"old"}]},{"role":"model","parts":[{"text":"answer"}]},{"role":"user","parts":[{"inlineData":{"mimeType":"image/png","data":"AA=="}}]}]}`,
			invalid: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input, turn, newUser, err := sr1Input([]byte(tc.body))
			if (err != nil) != tc.invalid || input != tc.input || turn != tc.turn || newUser != tc.newUser {
				t.Fatalf("input=%q turn=%q newUser=%t err=%v want=%q/%q/%t invalid=%t", input, turn, newUser, err, tc.input, tc.turn, tc.newUser, tc.invalid)
			}
		})
	}
}

type sr1InputScorer struct {
	sr1TestScorer
	input string
}

func (s *sr1InputScorer) ScoreSR1(ctx context.Context, input, tenantID string) (float64, error) {
	s.input = input
	return s.sr1TestScorer.ScoreSR1(ctx, input, tenantID)
}

func TestSR1NativeFormatsPreserveBothEscapePreferences(t *testing.T) {
	formats := []struct {
		name         string
		cold         string
		hard         string
		continuation string
		later        string
	}{
		{
			name:         "Bedrock",
			cold:         `{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`,
			hard:         `{"messages":[{"role":"user","content":[{"text":"hi"}]},{"role":"assistant","content":[{"text":"answer"}]},{"role":"user","content":[{"text":"hard"}]},{"role":"assistant","content":[{"text":"Here is"}]}]}`,
			continuation: `{"messages":[{"role":"user","content":[{"text":"hard"}]},{"role":"assistant","content":[{"toolUse":{"toolUseId":"a","name":"f","input":{}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"a","content":[{"text":"result"}]}}]}]}`,
			later:        `{"messages":[{"role":"user","content":[{"text":"even harder"}]}]}`,
		},
		{
			name:         "Gemini",
			cold:         `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`,
			hard:         `{"contents":[{"role":"user","parts":[{"text":"hi"}]},{"role":"model","parts":[{"text":"answer"}]},{"role":"user","parts":[{"text":"hard"}]},{"role":"model","parts":[{"text":"Here is"}]}]}`,
			continuation: `{"contents":[{"role":"user","parts":[{"text":"hard"}]},{"role":"model","parts":[{"functionCall":{"name":"f","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"name":"f","response":{"result":"done"}}}]}]}`,
			later:        `{"contents":[{"role":"user","parts":[{"text":"even harder"}]}]}`,
		},
	}
	for _, format := range formats {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/escape=%t", format.name, enabled), func(t *testing.T) {
				_, _, store := sr1Fixture(t)
				routes := modelRoutes("low", "mid", "high")
				cfg := tiersFor(routes, 0, .187, .45)
				cfg.SR1 = &registry.SR1Config{CacheTTLSeconds: 60, EscapeHatchEnabled: enabled}
				scorer := &sr1InputScorer{}
				s := NewSmartRouting(routes, cfg, scorer, store, nil)
				req := promptReq()
				req.SessionID, req.Body = "native", []byte(format.cold)
				ctx := context.Background()
				if got := s.Next(ctx, req, nil); got == nil || got.Model != "low" || scorer.input != "hi" || scorer.calls.Load() != 1 {
					t.Fatalf("native cold route=%v scorerInput=%q calls=%d", got, scorer.input, scorer.calls.Load())
				}
				scorer.score = 1
				wantModel, wantInput, wantCalls := "low", "hi", int64(1)
				if enabled {
					wantModel, wantInput, wantCalls = "mid", "hard", 2
				}
				for _, body := range []string{format.hard, format.hard, format.continuation, format.later} {
					req.Body = []byte(body)
					if got := s.Next(ctx, req, nil); got == nil || got.Model != wantModel || scorer.input != wantInput || scorer.calls.Load() != wantCalls {
						t.Fatalf("route=%v scorerInput=%q calls=%d want=%s/%q/%d", got, scorer.input, scorer.calls.Load(), wantModel, wantInput, wantCalls)
					}
				}
			})
		}
	}
}
