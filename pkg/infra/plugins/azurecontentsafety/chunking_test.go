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
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func utf16Len(s string) int { return len(utf16.Encode([]rune(s))) }

func run(t *testing.T, p *Plugin, mode policy.Mode, url string, body []byte) (*appplugins.Result, *Data, error) {
	t.Helper()
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, mode, settings(url, map[string]int{CategoryHate: 2}), requestContext(body))
	in.Event = event
	res, err := p.Execute(context.Background(), in)
	extras, _ := span.PluginAttrsCopy().Extras.(*Data)
	return res, extras, err
}

func TestEveryChunkFitsTheLimitInUTF16Units(t *testing.T) {
	t.Parallel()
	f := &limitedAzure{}
	srv := f.server(t)
	p := New(adapter.NewRegistry(), nil)
	_, data, err := run(t, p, policy.ModeEnforce, srv.URL,
		chatBody(t, map[string]string{"role": "user", "content": strings.Repeat("\U0001F600", 5001)}))
	require.NoError(t, err)
	sent := f.sent()
	require.GreaterOrEqual(t, len(sent), 2, "5001 emoji are 10002 UTF-16 units")
	for _, text := range sent {
		assert.LessOrEqual(t, utf16Len(text), azureTextLimit)
	}
	require.NotNil(t, data)
	assert.Equal(t, len(sent), data.ChunkCount)
}

func TestAConversationOfSixtyFourChunksIsEvaluatedAndSixtyFiveIsRefusedBeforeAnyCall(t *testing.T) {
	t.Parallel()
	atLimit := chunkUnits + (maxChunks-1)*(chunkUnits-chunkOverlap)
	require.Equal(t, maxChunks, textchunk.Count(strings.Repeat("a", atLimit), chunkSpec))
	require.Equal(t, maxChunks+1, textchunk.Count(strings.Repeat("a", atLimit+1), chunkSpec))

	t.Run("sixty-four", func(t *testing.T) {
		t.Parallel()
		f := &limitedAzure{}
		srv := f.server(t)
		p := New(adapter.NewRegistry(), nil)
		_, data, err := run(t, p, policy.ModeEnforce, srv.URL,
			chatBody(t, map[string]string{"role": "user", "content": strings.Repeat("a", atLimit)}))
		require.NoError(t, err)
		assert.Len(t, f.sent(), maxChunks)
		assert.Equal(t, maxChunks, data.ChunkCount)
		assert.Equal(t, "allowed", data.Decision)
	})
	t.Run("sixty-five", func(t *testing.T) {
		t.Parallel()
		f := &limitedAzure{}
		srv := f.server(t)
		p := New(adapter.NewRegistry(), nil)
		_, data, err := run(t, p, policy.ModeEnforce, srv.URL,
			chatBody(t, map[string]string{"role": "user", "content": strings.Repeat("a", atLimit+1)}))
		pe, ok := appplugins.AsPluginError(err)
		require.True(t, ok, "got %v", err)
		assert.Equal(t, http.StatusForbidden, pe.StatusCode)
		assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
		assert.Empty(t, f.sent(), "no call is made for a request that cannot be screened whole")
		assert.Equal(t, appplugins.DetailChunkLimit, data.FailureDetail)
		assert.Equal(t, "input", data.FailureClass)
	})
	t.Run("sixty-five in observe", func(t *testing.T) {
		t.Parallel()
		f := &limitedAzure{}
		srv := f.server(t)
		p := New(adapter.NewRegistry(), nil)
		res, data, err := run(t, p, policy.ModeObserve, srv.URL,
			chatBody(t, map[string]string{"role": "user", "content": strings.Repeat("a", atLimit+1)}))
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Equal(t, appplugins.DetailChunkLimit, data.FailureDetail)
	})
}

// An agent session: the harmful text is in the arguments of an assistant tool
// call and in a tool result, neither of which is a user turn.
func TestToolCallArgumentsAndToolResultsAreScreened(t *testing.T) {
	t.Parallel()
	cases := map[string][]byte{
		"tool call arguments": []byte(`{"model":"gpt-4o","messages":[
			{"role":"user","content":"look it up"},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"search","arguments":"{\"q\":\"FLAGGED query\"}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"ok"},
			{"role":"user","content":"thanks"}]}`),
		"tool result": []byte(`{"model":"gpt-4o","messages":[
			{"role":"user","content":"look it up"},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"search","arguments":"{}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"FLAGGED page"},
			{"role":"user","content":"thanks"}]}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := &limitedAzure{}
			srv := f.server(t)
			p := New(adapter.NewRegistry(), nil)
			_, _, err := run(t, p, policy.ModeEnforce, srv.URL, body)
			pe, ok := appplugins.AsPluginError(err)
			require.True(t, ok, "got %v", err)
			assert.Equal(t, http.StatusForbidden, pe.StatusCode)
		})
	}
}

func TestAChunkThatCannotBeInspectedIsTheWholeConversationsFailure(t *testing.T) {
	t.Parallel()
	long := chatBody(t, map[string]string{"role": "user", "content": strings.Repeat("word ", 5000)})
	categories := func(n int) string {
		return fmt.Sprintf(`{"categoriesAnalysis":[{"category":"Hate","severity":%d}]}`, n)
	}
	cases := []struct {
		name   string
		reply  func(call int) (int, string)
		detail string
		class  string
	}{
		{"a 429 on a conversation of several chunks is input", func(call int) (int, string) {
			if call == 2 {
				return http.StatusTooManyRequests, `{"error":{"code":"429","message":"Rate limit is exceeded. Try again in 1 seconds."}}`
			}
			return http.StatusOK, categories(0)
		}, appplugins.DetailThrottledOversize, "input"},
		{"a spent call volume quota is configuration", func(call int) (int, string) {
			if call == 2 {
				return http.StatusTooManyRequests, `{"error":{"code":"429","message":"Out of call volume quota for ContentSafety F0 pricing tier. Please retry after 2 days. To increase your call volume switch to a paid tier."}}`
			}
			return http.StatusOK, categories(0)
		}, appplugins.DetailProviderQuotaExhausted, "availability"},
		{"a 5xx is availability", func(call int) (int, string) {
			if call == 2 {
				return http.StatusServiceUnavailable, `{"error":{"code":"ServiceUnavailable"}}`
			}
			return http.StatusOK, categories(0)
		}, "", "availability"},
		{"a category missing from one chunk is availability", func(call int) (int, string) {
			if call == 2 {
				return http.StatusOK, `{"categoriesAnalysis":[]}`
			}
			return http.StatusOK, categories(0)
		}, CategoryHate, "availability"},
		{"azure refusing the content is input", func(call int) (int, string) {
			if call == 2 {
				return http.StatusBadRequest, `{"error":{"code":"InvalidRequestBody","message":"The text is not acceptable.","target":"text"}}`
			}
			return http.StatusOK, categories(0)
		}, appplugins.DetailProviderRejectedInput, "input"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				status, body := tc.reply(int(calls.Add(1)))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(srv.Close)
			p := New(adapter.NewRegistry(), nil)

			res, data, err := run(t, p, policy.ModeEnforce, srv.URL, long)
			assert.Equal(t, tc.class, data.FailureClass)
			assert.Equal(t, tc.detail, data.FailureDetail)
			if tc.class == "input" {
				pe, ok := appplugins.AsPluginError(err)
				require.True(t, ok, "got %v", err)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, appplugins.DecisionFailedOpen, data.Decision)
		})
	}
}

func TestABlockBeatsAFailureInAnotherChunk(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body analyzeRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"categoriesAnalysis":[{"category":"Hate","severity":6}]}`))
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), nil)
	_, data, err := run(t, p, policy.ModeEnforce, srv.URL,
		chatBody(t, map[string]string{"role": "user", "content": strings.Repeat("word ", 5000)}))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Equal(t, "blocked", data.Decision)
	assert.Equal(t, 6, data.Severities[CategoryHate])
}

func TestAnEnforceBlockStopsTheChunksThatHaveNotStarted(t *testing.T) {
	t.Parallel()
	blocking := func() (*httptest.Server, *atomic.Int32) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"categoriesAnalysis":[{"category":"Hate","severity":6}]}`))
		}))
		t.Cleanup(srv.Close)
		return srv, &calls
	}
	text := strings.Repeat("a", 400000)
	total := int32(textchunk.Count(text, chunkSpec))
	body := chatBody(t, map[string]string{"role": "user", "content": text})
	p := New(adapter.NewRegistry(), nil)

	enforceSrv, enforceCalls := blocking()
	_, _, err := run(t, p, policy.ModeEnforce, enforceSrv.URL, body)
	require.Error(t, err)
	assert.Less(t, enforceCalls.Load(), total, "the rest is skipped")

	observeSrv, observeCalls := blocking()
	res, data, err := run(t, p, policy.ModeObserve, observeSrv.URL, body)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "reported", data.Decision)
	assert.Equal(t, total, observeCalls.Load(), "observe screens every chunk")
}

// Chunks that never reached Azure because the request's own earlier chunks used
// the budget are the request's size, not Azure's availability.
func TestChunksThatNeverStartedWithinTheBudgetAreInput(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"categoriesAnalysis":[{"category":"Hate","severity":0}]}`))
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), nil)
	p.budget = 100 * time.Millisecond

	_, data, err := run(t, p, policy.ModeEnforce, srv.URL,
		chatBody(t, map[string]string{"role": "user", "content": strings.Repeat("a", 300000)}))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
	assert.Equal(t, appplugins.DetailChunkBudget, data.FailureDetail)
}

func TestTheWindowTelemetryIsGone(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(&Data{ChunkCount: 3})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "partial_window")
	assert.NotContains(t, string(raw), "chars_not_inspected")
	assert.Contains(t, string(raw), `"chunk_count":3`)
}

func TestA429IsRecordedAsThrottled(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"429","message":"Rate limit is exceeded. Try again in 1 seconds."}}`))
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), nil)
	res, data, err := run(t, p, policy.ModeEnforce, srv.URL, openAIRequestBody())
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, string(appplugins.FailureTransport), data.FailureReason)
	assert.Equal(t, appplugins.DetailThrottled, data.FailureDetail)
}
