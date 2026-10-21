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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/infra/complexity"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
)

// limitFirewall enforces the firewall's input limits in runes (Python len) and
// scores any prompt starting with "hard" as difficult.
type limitFirewall struct {
	mu          sync.Mutex
	maxInput    *int
	maxText     *int
	configCode  int
	rejected    int
	receivedLen []int
	received    []string
}

func (f *limitFirewall) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/v1/complexity/config":
			if f.configCode != 0 {
				w.WriteHeader(f.configCode)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"max_inputs": 1, "max_input_chars": f.maxInput, "max_text_chars": f.maxText})
		case "/v1/complexity":
			var body struct {
				Input string `json:"input"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode: %v", err)
			}
			n := utf8.RuneCountInString(body.Input)
			for _, limit := range []*int{f.maxInput, f.maxText} {
				if limit != nil && n > *limit {
					f.rejected++
					w.WriteHeader(http.StatusRequestEntityTooLarge)
					return
				}
			}
			if f.maxInput == nil && f.maxText == nil && n > 32768 {
				f.rejected++
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			f.receivedLen = append(f.receivedLen, n)
			f.received = append(f.received, body.Input)
			score := 0.1
			if strings.HasPrefix(body.Input, "hard") {
				score = 0.9
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"revision": "rev", "score": score, "raw_score": score})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func ptr(v int) *int { return &v }

func routeLimitPrompt(t *testing.T, fw *limitFirewall, prompt string) (string, int) {
	t.Helper()
	srv := httptest.NewServer(fw.handler(t))
	t.Cleanup(srv.Close)
	scorer := complexity.NewClient(srv.URL, firewall.NewTokenProvider("synthetic-signing-secret"), time.Second, "rev")
	// Scoring never waits on /config, so load the limits first.
	_ = scorer.RefreshLimits(context.Background())
	routes := modelRoutes("weak", "mid", "strong")
	cfg := tiersFor(routes, 0.0, 0.187, 0.45)
	s := NewSmartRouting(routes, cfg, scorer, nil, nil)
	raw, err := json.Marshal(map[string]string{"prompt": prompt})
	if err != nil {
		t.Fatal(err)
	}
	got := s.Next(context.Background(), &infracontext.RequestContext{Body: raw, GatewayID: "gw_1"}, nil)
	if got == nil {
		t.Fatal("expected a route")
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return got.Model, fw.rejected
}

func TestSR1OverLimitPromptIsCutNotRejected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		fw        *limitFirewall
		prompt    string
		wantModel string
		wantRunes int
	}{
		{"default limit, ascii, hard prefix", &limitFirewall{maxInput: ptr(32768)}, "hard" + strings.Repeat("x", 100000), "strong", 32768},
		{"default limit, easy prefix routes weak", &limitFirewall{maxInput: ptr(32768)}, "easy" + strings.Repeat("x", 100000), "weak", 32768},
		{"multi-byte runes counted as runes", &limitFirewall{maxInput: ptr(1000)}, "hard" + strings.Repeat("日本語🙂", 2000), "strong", 1000},
		{"max_text_chars stricter than max_input_chars", &limitFirewall{maxInput: ptr(32768), maxText: ptr(500)}, "hard" + strings.Repeat("é", 5000), "strong", 500},
		{"max_input_chars stricter than max_text_chars", &limitFirewall{maxInput: ptr(300), maxText: ptr(5000)}, "hard" + strings.Repeat("x", 5000), "strong", 300},
		{"config unavailable falls back to 32768", &limitFirewall{configCode: http.StatusInternalServerError}, "hard" + strings.Repeat("🙂", 40000), "strong", 32768},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			model, rejected := routeLimitPrompt(t, tc.fw, tc.prompt)
			if rejected != 0 {
				t.Fatalf("firewall rejected %d request(s) with 413", rejected)
			}
			if model != tc.wantModel {
				t.Fatalf("routed to %q, want %q", model, tc.wantModel)
			}
			if len(tc.fw.receivedLen) != 1 || tc.fw.receivedLen[0] != tc.wantRunes {
				t.Fatalf("sent rune counts %v, want [%d]", tc.fw.receivedLen, tc.wantRunes)
			}
			if !utf8.ValidString(tc.fw.received[0]) || !strings.HasPrefix(tc.prompt, tc.fw.received[0]) {
				t.Fatal("sent input is not a valid prefix of the prompt")
			}
		})
	}
}

func TestSR1WithinLimitPromptSentUnchanged(t *testing.T) {
	t.Parallel()
	prompt := "hard " + strings.Repeat("日本語🙂", 100) // exactly within limit, multi-byte
	fw := &limitFirewall{maxInput: ptr(utf8.RuneCountInString(prompt))}
	model, rejected := routeLimitPrompt(t, fw, prompt)
	if rejected != 0 || model != "strong" {
		t.Fatalf("model=%q rejected=%d", model, rejected)
	}
	if len(fw.received) != 1 || fw.received[0] != prompt {
		t.Fatal("within-limit prompt was altered")
	}
}
