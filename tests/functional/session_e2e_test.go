//go:build functional

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

package functional_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sessionHeader = "X-Session-Id"

// newResponsesUpstream answers every request with a completed OpenAI Responses
// object whose id is resp_<prefix>_<n>, so each turn has a distinct id.
func newResponsesUpstream(t *testing.T, prefix string) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	var turn int64
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		n := atomic.AddInt64(&turn, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"id":"resp_%s_%d","object":"response","status":"completed","model":"gpt-4o-mini",`+
				`"output":[{"type":"message","id":"msg_%d","role":"assistant","status":"completed",`+
				`"content":[{"type":"output_text","text":"ok","annotations":[]}]}],`+
				`"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`,
			prefix, n, n,
		)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func TestSession_ResponsesChainSharesOneSession(t *testing.T) {
	defer Track(t, "Session")()

	prefix := uniqueName("chain")
	up := newResponsesUpstream(t, prefix)
	apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")
	path := "/" + slug + "/v1/responses"

	status, headers, body := proxyPost(t, apiKey, path, map[string]any{"model": "@openai/gpt-4o-mini", "input": "first"})
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	first := headers.Get(sessionHeader)
	require.NotEmpty(t, first, "the first turn of a chain gets a generated session id")

	status, headers, body = proxyPost(t, apiKey, path, map[string]any{
		"model": "@openai/gpt-4o-mini", "input": "second", "previous_response_id": fmt.Sprintf("resp_%s_1", prefix),
	})
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, first, headers.Get(sessionHeader), "a continuation inherits the session of the turn it continues")

	status, headers, body = proxyPost(t, apiKey, path, map[string]any{
		"model": "@openai/gpt-4o-mini", "input": "branch", "previous_response_id": fmt.Sprintf("resp_%s_1", prefix),
	})
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, first, headers.Get(sessionHeader), "a branch from an earlier turn keeps the session")

	status, headers, body = proxyPost(t, apiKey, path, map[string]any{
		"model": "@openai/gpt-4o-mini", "input": "unknown", "previous_response_id": "resp_never_recorded",
	})
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.NotEqual(t, first, headers.Get(sessionHeader), "an unknown turn starts a new session")
}

func TestSession_ResponsesConversationIsTheSession(t *testing.T) {
	defer Track(t, "Session")()

	up := newResponsesUpstream(t, uniqueName("conv"))
	apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

	status, headers, body := proxyPost(t, apiKey, "/"+slug+"/v1/responses", map[string]any{
		"model": "@openai/gpt-4o-mini", "input": "hi", "conversation": map[string]any{"id": "conv_functional_1"},
	})
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "conv_functional_1", headers.Get(sessionHeader))

	status, _, body = proxyPost(t, apiKey, "/"+slug+"/v1/responses", map[string]any{
		"model": "@openai/gpt-4o-mini", "input": "again", "conversation": "conv_functional_1",
	})
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.NotContains(t, string(up.LastBody()), "previous_response_id",
		"a conversation request must not get a previous_response_id injected")
}
