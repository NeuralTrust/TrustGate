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

package openaimoderation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// moderationStub answers like POST /v1/moderations: one result per request, in
// the documented shape, and records the size of every text it was sent.
type moderationStub struct {
	mu    sync.Mutex
	sizes []int
	texts []string
	flag  func(text string) bool
}

func (s *moderationStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model string `json:"model"`
			Input []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		text := ""
		for _, in := range body.Input {
			text += in.Text
		}
		s.mu.Lock()
		s.sizes = append(s.sizes, len(text))
		s.texts = append(s.texts, text)
		s.mu.Unlock()
		flagged := s.flag != nil && s.flag(text)
		score := 0.01
		if flagged {
			score = 0.93
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":%t,"categories":{"hate":%t},"category_scores":{"hate":%v}}]}`,
			flagged, flagged, score)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (s *moderationStub) requests() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.sizes...)
}

// agentSession is the history of a long agent run: a system prompt and pairs of
// a question and a large tool or retrieval result, 300 KiB in all.
func agentSession(t *testing.T, kib int) []byte {
	t.Helper()
	messages := []map[string]string{{"role": "system", "content": "you are a research agent"}}
	for i := 0; i < kib/10; i++ {
		messages = append(messages,
			map[string]string{"role": "user", "content": fmt.Sprintf("question %d", i)},
			map[string]string{"role": "tool", "content": strings.Repeat("an ordinary retrieved sentence. ", 330)},
		)
	}
	raw, err := json.Marshal(map[string]any{"model": "gpt-4o", "messages": messages})
	require.NoError(t, err)
	return raw
}

func TestALongBenignAgentSessionIsModeratedNotRefused(t *testing.T) {
	t.Parallel()
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			stub := &moderationStub{}
			srv := stub.server(t)
			p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
			event, span := newEvent()
			req := requestContext()
			req.Body = agentSession(t, 300)
			in := execInput(policy.StagePreRequest, mode, blockSettings(), req, nil, event)

			res, err := p.Execute(context.Background(), in)

			require.NoError(t, err)
			require.NotNil(t, res)
			sizes := stub.requests()
			assert.GreaterOrEqual(t, len(sizes), 10, "300 KiB needs at least ten requests of 32 KiB")
			for _, n := range sizes {
				assert.LessOrEqual(t, n, 32768)
			}
			extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
			require.True(t, ok)
			assert.Equal(t, "allowed", extras.Decision)
			assert.Empty(t, extras.FailureReason)
		})
	}
}
