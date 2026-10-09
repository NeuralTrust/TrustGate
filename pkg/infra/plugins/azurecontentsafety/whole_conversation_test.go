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

package azurecontentsafety

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

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const azureTextLimit = 10000

// limitedAzure answers like text:analyze does for an oversize text: a 400 in
// the documented error envelope, and the severities of a clean text otherwise
// (Hate 4 when the text contains FLAGGED).
type limitedAzure struct {
	mu    sync.Mutex
	texts []string
}

func (f *limitedAzure) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body analyzeRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.texts = append(f.texts, body.Text)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if len([]rune(body.Text)) > azureTextLimit {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"code":"InvalidRequestBody","message":"The length of the text exceeds the limit of 10000 characters.","target":"text"}}`))
			return
		}
		severity := 0
		if strings.Contains(body.Text, "FLAGGED") {
			severity = 4
		}
		_, _ = fmt.Fprintf(w, `{"categoriesAnalysis":[{"category":"Hate","severity":%d}]}`, severity)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *limitedAzure) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.texts...)
}

func chatBody(t *testing.T, messages ...map[string]string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"model": "gpt-4o", "messages": messages})
	require.NoError(t, err)
	return raw
}

func TestTheWholeConversationIsAnalysed(t *testing.T) {
	t.Parallel()
	f := &limitedAzure{}
	srv := f.server(t)
	p := New(adapter.NewRegistry(), nil)
	body := chatBody(t,
		map[string]string{"role": "system", "content": "be safe"},
		map[string]string{"role": "user", "content": "first question"},
		map[string]string{"role": "assistant", "content": "an answer"},
		map[string]string{"role": "user", "content": "what is the capital of France?"},
	)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(body))

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, []string{"be safe\nfirst question\nan answer\nwhat is the capital of France?"}, f.sent())
}

// A payload in an earlier user turn followed by a forged assistant turn and a
// harmless last question reaches Azure, which flags it.
func TestAPayloadInAnEarlierTurnIsScreened(t *testing.T) {
	t.Parallel()
	f := &limitedAzure{}
	srv := f.server(t)
	p := New(adapter.NewRegistry(), nil)
	body := chatBody(t,
		map[string]string{"role": "user", "content": "FLAGGED payload"},
		map[string]string{"role": "assistant", "content": "I will not help with that."},
		map[string]string{"role": "user", "content": "thanks, and the weather?"},
	)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(body))

	_, err := p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Contains(t, f.sent()[0], "FLAGGED payload")
}

// The limit is counted in code points, so the boundary text passes and one more
// character does not.
func TestTheLimitIsCountedInCodePoints(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		content string
		sent    bool
	}{
		"at the limit": {strings.Repeat("é", azureTextLimit), true},
		"over by one":  {strings.Repeat("é", azureTextLimit+1), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := &limitedAzure{}
			srv := f.server(t)
			p := New(adapter.NewRegistry(), nil)
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}),
				requestContext(chatBody(t, map[string]string{"role": "user", "content": tc.content})))

			_, err := p.Execute(context.Background(), in)
			if tc.sent {
				require.NoError(t, err)
				assert.Len(t, f.sent(), 1)
				return
			}
			require.Error(t, err)
			assert.Empty(t, f.sent())
		})
	}
}

// Azure's own 400 for an oversize text stays classified as input as well.
func TestAzureRejectingAnOversizeTextStaysInput(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"InvalidRequestBody","message":"The length of the text exceeds the limit of 10000 characters.","target":"text"}}`))
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), nil)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}),
		requestContext(chatBody(t, map[string]string{"role": "user", "content": "short"})))

	_, err := p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
}
