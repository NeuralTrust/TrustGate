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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// The ceiling is what half of the budget admits: with the 10 s budget, 4
// parallel calls and a 1 s reserve, five rounds, so 20 chunks.
func TestAConversationAtTheCeilingIsEvaluatedAndOneUnitMoreIsRefusedBeforeAnyCall(t *testing.T) {
	t.Parallel()
	ceiling := textchunk.MaxChunks(maxChunks, evalParallel, callReserve, evaluationBudget)
	require.Equal(t, 60, ceiling)
	atLimit := chunkUnits + (ceiling-1)*(chunkUnits-chunkOverlap)
	require.Equal(t, ceiling, textchunk.Count(strings.Repeat("a", atLimit), chunkSpec))
	require.Equal(t, ceiling+1, textchunk.Count(strings.Repeat("a", atLimit+1), chunkSpec))

	t.Run("at the ceiling", func(t *testing.T) {
		t.Parallel()
		f := &limitedAzure{}
		srv := f.server(t)
		p := New(adapter.NewRegistry(), nil)
		_, data, err := run(t, p, policy.ModeEnforce, srv.URL,
			chatBody(t, map[string]string{"role": "user", "content": strings.Repeat("a", atLimit)}))
		require.NoError(t, err)
		assert.Len(t, f.sent(), ceiling)
		assert.Equal(t, ceiling, data.ChunkCount)
		assert.Equal(t, "allowed", data.Decision)
	})
	t.Run("above the ceiling", func(t *testing.T) {
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
	t.Run("above the ceiling in observe", func(t *testing.T) {
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
	const lateMarker = " ZZLATEZZ"
	long := chatBody(t, map[string]string{"role": "user", "content": strings.Repeat("word ", 12000) + lateMarker})
	categories := func(n int) string {
		return fmt.Sprintf(`{"categoriesAnalysis":[{"category":"Hate","severity":%d}]}`, n)
	}
	cases := []struct {
		name   string
		reply  func(call int, text string) (int, string)
		detail string
		class  string
	}{
		{"a 429 on a chunk dispatched after the first round is input", func(_ int, text string) (int, string) {
			if strings.Contains(text, lateMarker) {
				return http.StatusTooManyRequests, `{"error":{"code":"429","message":"Rate limit is exceeded. Try again in 1 seconds."}}`
			}
			return http.StatusOK, categories(0)
		}, appplugins.DetailThrottledOversize, "input"},
		{"a spent call volume quota is configuration", func(call int, _ string) (int, string) {
			if call == 2 {
				return http.StatusTooManyRequests, `{"error":{"code":"429","message":"Out of call volume quota for ContentSafety F0 pricing tier. Please retry after 2 days. To increase your call volume switch to a paid tier."}}`
			}
			return http.StatusOK, categories(0)
		}, appplugins.DetailProviderQuotaExhausted, "availability"},
		{"a 5xx is availability", func(call int, _ string) (int, string) {
			if call == 2 {
				return http.StatusServiceUnavailable, `{"error":{"code":"ServiceUnavailable"}}`
			}
			return http.StatusOK, categories(0)
		}, "", "availability"},
		{"a category missing from one chunk is availability", func(call int, _ string) (int, string) {
			if call == 2 {
				return http.StatusOK, `{"categoriesAnalysis":[]}`
			}
			return http.StatusOK, categories(0)
		}, CategoryHate, "availability"},
		{"azure refusing the content is input", func(call int, _ string) (int, string) {
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
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				status, body := tc.reply(int(calls.Add(1)), string(raw))
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
	text := strings.Repeat("a", 150000)
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

// Every call hangs past the budget: the provider is down or slow, and the chunks
// that never started because its calls used the time are not the request's size.
func TestEveryCallHangingPastTheBudgetFailsOpen(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"categoriesAnalysis":[{"category":"Hate","severity":0}]}`))
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), nil)
	p.budget = 800 * time.Millisecond
	text := strings.Repeat("a", 50000)
	require.Equal(t, 6, textchunk.Count(text, chunkSpec))
	require.GreaterOrEqual(t, textchunk.MaxChunks(maxChunks, evalParallel, callReserve, p.budget), 6)

	res, data, err := run(t, p, policy.ModeEnforce, srv.URL, chatBody(t, map[string]string{"role": "user", "content": text}))

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "availability", data.FailureClass)
	assert.Equal(t, appplugins.DecisionFailedOpen, data.Decision)
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

// A secret that a cut falls inside is seen whole in the next chunk when the
// overlap holds it: here 1,500 of its 1,900 units are in the first chunk.
func TestASecretThatACutFallsInsideIsSeenWholeInOneChunk(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("SECRET-BEGIN\n")
	for b.Len() < 1900-len("SECRET-END") {
		b.WriteString(strings.Repeat("k", 63) + "\n")
	}
	b.WriteString("SECRET-END")
	secret := b.String()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body analyzeRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		severity := 0
		if strings.Contains(body.Text, "SECRET-BEGIN") && strings.Contains(body.Text, "SECRET-END") {
			severity = 4
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"categoriesAnalysis":[{"category":"Hate","severity":%d}]}`, severity)
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), nil)
	text := strings.Repeat("an ordinary word ", 600)[:chunkUnits-1500] + " " + secret + " " + strings.Repeat("an ordinary word ", 200)

	_, _, err := run(t, p, policy.ModeEnforce, srv.URL, chatBody(t, map[string]string{"role": "user", "content": text}))

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
}

// throttlingAzure answers 429 to the requests whose text throttle accepts, with a
// severity-0 verdict to the rest, and counts every request.
func throttlingAzure(t *testing.T, throttle func(text string) bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if throttle(string(raw)) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":"429","message":"Rate limit is exceeded. Try again in 1 seconds."}}`))
			return
		}
		_, _ = w.Write([]byte(`{"categoriesAnalysis":[{"category":"Hate","severity":0}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

const firstChunkMarker = "FIRST-CHUNK-ONLY"

func twoChunkConversation(t *testing.T) []byte {
	t.Helper()
	text := firstChunkMarker + strings.Repeat("a", 15000)
	require.Equal(t, 2, textchunk.Count(text, chunkSpec))
	return chatBody(t, map[string]string{"role": "user", "content": text})
}

// A throttle on the first chunk of a conversation that survives the one retry is
// other traffic: it fails open, however many conversations are in flight.
func TestAThrottleOnTheFirstChunkFailsOpen(t *testing.T) {
	t.Parallel()
	srv, _ := throttlingAzure(t, func(text string) bool { return strings.Contains(text, firstChunkMarker) })
	p := New(adapter.NewRegistry(), nil)
	body := twoChunkConversation(t)

	var wg sync.WaitGroup
	results := make([]*Data, 2)
	errs := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i], errs[i] = run(t, p, policy.ModeEnforce, srv.URL, body)
		}()
	}
	wg.Wait()
	for i := range results {
		require.NoError(t, errs[i])
		assert.Equal(t, appplugins.DetailThrottled, results[i].FailureDetail)
		assert.Equal(t, "availability", results[i].FailureClass)
		assert.Equal(t, appplugins.DecisionFailedOpen, results[i].Decision)
	}
}

// A throttle on a later chunk of the first round, which the request sent beside
// its first, is input once the retry has failed too.
func TestAThrottleOnALaterChunkOfTheFirstRoundIsInput(t *testing.T) {
	t.Parallel()
	srv, _ := throttlingAzure(t, func(text string) bool { return !strings.Contains(text, firstChunkMarker) })
	p := New(adapter.NewRegistry(), nil)

	_, data, err := run(t, p, policy.ModeEnforce, srv.URL, twoChunkConversation(t))

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
	assert.Equal(t, appplugins.DetailThrottledOversize, data.FailureDetail)
	assert.Equal(t, "input", data.FailureClass)
}

func TestAThrottleOnASingleChunkFailsOpenAfterOneRetry(t *testing.T) {
	t.Parallel()
	srv, calls := throttlingAzure(t, func(string) bool { return true })
	p := New(adapter.NewRegistry(), nil)

	_, data, err := run(t, p, policy.ModeEnforce, srv.URL, chatBody(t, map[string]string{"role": "user", "content": "hello"}))

	require.NoError(t, err)
	assert.Equal(t, appplugins.DetailThrottled, data.FailureDetail)
	assert.Equal(t, "availability", data.FailureClass)
	assert.EqualValues(t, 2, calls.Load())
}

func TestAThrottleThatSucceedsOnRetryGivesTheNormalVerdict(t *testing.T) {
	t.Parallel()
	var first atomic.Bool
	srv, _ := throttlingAzure(t, func(string) bool { return first.CompareAndSwap(false, true) })
	p := New(adapter.NewRegistry(), nil)

	res, data, err := run(t, p, policy.ModeEnforce, srv.URL, twoChunkConversation(t))

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "allowed", data.Decision)
	assert.Empty(t, data.FailureDetail)
}

// A parent whose deadline passes is not a client that left: the time ran out, so
// the budget rule reads it, and calls that hung until it are the provider being
// slow.
func TestAParentDeadlineFollowsTheBudgetRule(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"categoriesAnalysis":[{"category":"Hate","severity":0}]}`))
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), nil)
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}),
		requestContext(chatBody(t, map[string]string{"role": "user", "content": strings.Repeat("a", 100000)})))
	in.Event = event
	parent, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	t.Cleanup(cancel)

	res, err := p.Execute(parent, in)

	require.NoError(t, err)
	require.NotNil(t, res)
	extras, _ := span.PluginAttrsCopy().Extras.(*Data)
	require.NotNil(t, extras)
	assert.Equal(t, "availability", extras.FailureClass)
}

// A provider that hangs is cut by the call's own timeout, not by the evaluation's
// budget: the request fails open after about one call.
func TestAHangFailsOpenAtTheCallTimeoutNotTheBudget(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), nil)
	p.client.http.Timeout = 400 * time.Millisecond
	require.Equal(t, evaluationBudget, p.budget)

	started := time.Now()
	res, data, err := run(t, p, policy.ModeEnforce, srv.URL,
		chatBody(t, map[string]string{"role": "user", "content": strings.Repeat("a", 50000)}))

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Less(t, time.Since(started), 5*time.Second, "far below the evaluation budget")
	assert.Equal(t, "availability", data.FailureClass)
	assert.Equal(t, appplugins.DecisionFailedOpen, data.Decision)
}
