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
// the documented error envelope, and the severities of a clean text otherwise.
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
		_, _ = w.Write([]byte(`{"categoriesAnalysis":[{"category":"Hate","severity":0}]}`))
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

// Only the last user turn is analysed, as bedrock_guardrail and
// google_model_armor do: a long system prompt or a long history must not push
// a short question over the 10K characters Azure accepts and refuse it.
func TestOnlyTheLastUserTurnIsAnalysed(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("the quick brown fox ", 800)
	f := &limitedAzure{}
	srv := f.server(t)
	p := New(adapter.NewRegistry(), nil)
	body := chatBody(t,
		map[string]string{"role": "system", "content": long},
		map[string]string{"role": "user", "content": long},
		map[string]string{"role": "assistant", "content": long},
		map[string]string{"role": "user", "content": "what is the capital of France?"},
	)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(body))

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, []string{"what is the capital of France?"}, f.sent())
}

func TestAnOversizeLastUserTurnIsAnInputFailure(t *testing.T) {
	t.Parallel()
	f := &limitedAzure{}
	srv := f.server(t)
	p := New(adapter.NewRegistry(), nil)
	body := chatBody(t,
		map[string]string{"role": "system", "content": "be safe"},
		map[string]string{"role": "user", "content": strings.Repeat("x", azureTextLimit+1)},
	)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(body))

	_, err := p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
}
