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

package googlemodelarmor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// armorScript answers each sanitize call by a function of its number and the
// text it carried, and keeps what it was sent.
type armorScript struct {
	*modelArmorStub
	mu2    sync.Mutex
	texts  []string
	prompt []string
}

func newArmorScript(t *testing.T, answer func(call int, text string) (int, string)) *armorScript {
	t.Helper()
	s := &armorScript{modelArmorStub: &modelArmorStub{}}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			UserPromptData struct {
				Text string `json:"text"`
			} `json:"userPromptData"`
			ModelResponseData struct {
				Text string `json:"text"`
			} `json:"modelResponseData"`
			UserPrompt string `json:"userPrompt"`
		}
		_ = json.Unmarshal(raw, &req)
		text := req.UserPromptData.Text + req.ModelResponseData.Text
		s.mu2.Lock()
		s.texts = append(s.texts, text)
		s.prompt = append(s.prompt, req.UserPrompt)
		call := len(s.texts)
		s.mu2.Unlock()
		status, body := answer(call, text)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *armorScript) sent() []string {
	s.mu2.Lock()
	defer s.mu2.Unlock()
	return append([]string(nil), s.texts...)
}

func armorPlain(bytes int) string {
	return strings.Repeat("an ordinary sentence of benign words. ", bytes/38+1)[:bytes]
}

func chatBody(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"model": "gpt-4o", "messages": []map[string]string{{"role": "user", "content": text}}})
	require.NoError(t, err)
	return raw
}

func allowAll(int, string) (int, string) { return http.StatusOK, allowResponse }

func TestALongTextIsSentInChunksUnderTheTokenLimit(t *testing.T) {
	t.Parallel()
	for _, stage := range []policy.Stage{policy.StagePreRequest, policy.StagePreResponse} {
		t.Run(string(stage), func(t *testing.T) {
			t.Parallel()
			s := newArmorScript(t, allowAll)
			p := pluginWithStub(s.modelArmorStub)
			event, span := newStreamEvent()
			text := armorPlain(300 << 10)
			var in appplugins.ExecInput
			if stage == policy.StagePreRequest {
				in = execInput(stage, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, text)), nil)
			} else {
				response := []byte(`{"id":"r1","model":"gpt-4o","choices":[{"message":{"role":"assistant","content":"` + text + `"},"finish_reason":"stop"}]}`)
				in = execInput(stage, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, strings.Repeat("q", 20000))), respCtx(response, false))
			}
			in.Event = event

			res, err := p.Execute(context.Background(), in)

			assertPassThrough(t, res, err)
			sent := s.sent()
			assert.Len(t, sent, 6, "300 KiB in chunks of 57,344 bytes that share 2,048")
			for i, chunk := range sent {
				assert.LessOrEqual(t, len(chunk), chunkBytes)
				if stage == policy.StagePreResponse {
					assert.LessOrEqual(t, len(chunk)+len(s.prompt[i]), 65536, "the response and its correlation prompt stay within the token limit")
				}
			}
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, 6, data.ChunkCount)
			assert.Equal(t, "allowed", data.Decision)
		})
	}
}

func TestASkippedFilterOnOneChunkRefusesTheRequest(t *testing.T) {
	t.Parallel()
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			s := newArmorScript(t, func(call int, _ string) (int, string) {
				if call == 4 {
					return http.StatusOK, tokenLimitSkipResponse
				}
				return http.StatusOK, allowResponse
			})
			p := pluginWithStub(s.modelArmorStub)
			event, span := newStreamEvent()
			in := execInput(policy.StagePreRequest, mode, modelArmorSettings(), reqCtx(chatBody(t, armorPlain(300<<10))), nil)
			in.Event = event

			res, err := p.Execute(context.Background(), in)

			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, appplugins.DetailFilterNotExecuted, data.FailureDetail)
			assert.Equal(t, "input", data.FailureClass)
			if mode == policy.ModeEnforce {
				pe, isPE := appplugins.AsPluginError(err)
				require.True(t, isPE, "got res=%v err=%v", res, err)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
				return
			}
			assertPassThrough(t, res, err)
		})
	}
}

func TestABlockOnAnyChunkBlocksAndEnforceStopsTheRest(t *testing.T) {
	t.Parallel()
	answer := func(_ int, text string) (int, string) {
		if strings.HasPrefix(text, "BLOCKME") {
			return http.StatusOK, raiBlockResponse
		}
		return http.StatusOK, allowResponse
	}
	text := "BLOCKME " + armorPlain(800 << 10)[:700<<10]
	total := 0
	{
		s := newArmorScript(t, answer)
		p := pluginWithStub(s.modelArmorStub)
		in := execInput(policy.StagePreRequest, policy.ModeObserve, modelArmorSettings(), reqCtx(chatBody(t, text)), nil)
		res, err := p.Execute(context.Background(), in)
		assertPassThrough(t, res, err)
		total = len(s.sent())
	}
	require.Greater(t, total, 8)

	s := newArmorScript(t, answer)
	p := pluginWithStub(s.modelArmorStub)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, text)), nil)
	_, err := p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Less(t, len(s.sent()), total)
}

func deidentifyAnswer(text string) string {
	masked := strings.ReplaceAll(text, "victim@example.com", "[EMAIL_ADDRESS]")
	return sdpAnonymizeResponse(masked)
}

func TestAMaskInTwoChunksAcrossTheOverlapIsAppliedOnce(t *testing.T) {
	t.Parallel()
	s := newArmorScript(t, func(_ int, text string) (int, string) {
		if strings.Contains(text, "victim@example.com") {
			return http.StatusOK, deidentifyAnswer(text)
		}
		return http.StatusOK, allowResponse
	})
	p := pluginWithStub(s.modelArmorStub)
	pad := armorPlain(chunkBytes - chunkOverlap/2 - 8)
	text := pad + " victim@example.com " + armorPlain(30000)
	settings := modelArmorSettings()
	settings["sdp_action"] = sdpActionAnonymize
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings, reqCtx(chatBody(t, text)), nil)

	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	var req struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(res.RequestBody, &req))
	got := req.Messages[len(req.Messages)-1].Content
	assert.Equal(t, strings.ReplaceAll(text, "victim@example.com", "[EMAIL_ADDRESS]"), got)
	assert.Equal(t, 1, strings.Count(got, "[EMAIL_ADDRESS]"))
	hits := 0
	for _, sent := range s.sent() {
		if strings.Contains(sent, "victim@example.com") {
			hits++
		}
	}
	assert.GreaterOrEqual(t, hits, 1)
}

// A chunk that failed for a reason the request did not cause releases its text,
// but a mask another chunk produced is still applied: forwarding the original
// would send what that chunk masked.
func TestAMaskSurvivesAnAvailabilityFailureOnAnotherChunk(t *testing.T) {
	t.Parallel()
	// The failing chunk is named by what it carries, never by arrival order: the
	// chunks run concurrently, so the nth request is a different chunk from run
	// to run, and it can be the one that holds the email.
	const failing = "FAILS-WITH-503"
	s := newArmorScript(t, func(_ int, text string) (int, string) {
		if strings.Contains(text, "victim@example.com") {
			return http.StatusOK, deidentifyAnswer(text)
		}
		if strings.Contains(text, failing) {
			return http.StatusServiceUnavailable, rpcUnavailable
		}
		return http.StatusOK, allowResponse
	})
	p := pluginWithStub(s.modelArmorStub)
	plain := armorPlain(200 << 10)
	text := "write to victim@example.com " + plain[:120<<10] + " " + failing + " " + plain[120<<10:]
	settings := modelArmorSettings()
	settings["sdp_action"] = sdpActionAnonymize
	event, span := newStreamEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings, reqCtx(chatBody(t, text)), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.RequestBody)
	assert.NotContains(t, string(res.RequestBody), "victim@example.com")
	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "anonymized", data.Decision)
	assert.Equal(t, "availability", data.FailureClass)
	assert.Equal(t, string(appplugins.FailureTransport), data.FailureReason)
}

func TestAProviderRateLimitIsRecordedAsThrottled(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusTooManyRequests, rpcResourceExhausted))
	event, span := newStreamEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, appplugins.DetailThrottled, data.FailureDetail)
	assert.Equal(t, "availability", data.FailureClass)
}

func TestSixteenChunksAreEvaluatedAndSeventeenAreRefused(t *testing.T) {
	t.Parallel()
	stride := chunkBytes - chunkOverlap
	for _, tc := range []struct {
		name   string
		bytes  int
		calls  int
		refuse bool
	}{
		{"sixteen", chunkBytes + 15*stride, 16, false},
		{"seventeen", chunkBytes + 15*stride + 1, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newArmorScript(t, allowAll)
			p := pluginWithStub(s.modelArmorStub)
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, strings.Repeat("a", tc.bytes))), nil)

			res, err := p.Execute(context.Background(), in)

			assert.Len(t, s.sent(), tc.calls)
			if tc.refuse {
				pe, ok := appplugins.AsPluginError(err)
				require.True(t, ok, "got %v", err)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
				return
			}
			assertPassThrough(t, res, err)
		})
	}
}

func TestAChunkedEvaluationWithNoFindingRecordsTheFilterVersion(t *testing.T) {
	t.Parallel()
	versioned := strings.TrimSuffix(allowResponse, sanitizeClose) +
		`},"sanitizationMetadata":{"filterVersionConfig":{"filterVersion":"v3","filterVersionAlias":"FILTER_VERSION_ALIAS_STABLE"}}}}`
	s := newArmorScript(t, func(int, string) (int, string) { return http.StatusOK, versioned })
	p := pluginWithStub(s.modelArmorStub)
	event, span := newStreamEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, armorPlain(200<<10))), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Greater(t, data.ChunkCount, 1)
	assert.Equal(t, "allowed", data.Decision)
	assert.Equal(t, "v3", data.FilterVersion)
}

// A throttle on a text that was split into several calls may be that text's own
// size, so it is input; on a text of one call it stays the provider's load.
func TestAThrottleOnALongTextIsInput(t *testing.T) {
	t.Parallel()
	const lateMarker = " ZZLATEZZ"
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			s := newArmorScript(t, func(_ int, text string) (int, string) {
				if strings.Contains(text, lateMarker) {
					return http.StatusTooManyRequests, rpcResourceExhausted
				}
				return http.StatusOK, allowResponse
			})
			p := pluginWithStub(s.modelArmorStub)
			event, span := newStreamEvent()
			in := execInput(policy.StagePreRequest, mode, modelArmorSettings(), reqCtx(chatBody(t, armorPlain(300<<10)+lateMarker)), nil)
			in.Event = event

			res, err := p.Execute(context.Background(), in)

			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, appplugins.DetailThrottledOversize, data.FailureDetail)
			assert.Equal(t, "input", data.FailureClass)
			if mode == policy.ModeEnforce {
				pe, isPE := appplugins.AsPluginError(err)
				require.True(t, isPE, "got res=%v err=%v", res, err)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
				return
			}
			assertPassThrough(t, res, err)
		})
	}
}

// pemLike is a secret as long as a PEM key or a service-account JSON, with the
// line breaks such text has: a chunk may end at one of them, inside the secret.
func pemLike(bytes int) string {
	var b strings.Builder
	b.WriteString("SECRET-BEGIN\n")
	for b.Len() < bytes-len("SECRET-END") {
		b.WriteString(strings.Repeat("k", 63) + "\n")
	}
	b.WriteString("SECRET-END")
	return b.String()
}

// The overlap is what lets a secret that a cut falls inside be seen whole in the
// next chunk: here 3,000 of its 3,500 bytes are in the first chunk.
func TestALongSecretThatACutFallsInsideIsSeenWholeInOneChunk(t *testing.T) {
	t.Parallel()
	s := newArmorScript(t, func(_ int, text string) (int, string) {
		if strings.Contains(text, "SECRET-BEGIN") && strings.Contains(text, "SECRET-END") {
			return http.StatusOK, raiBlockResponse
		}
		return http.StatusOK, allowResponse
	})
	p := pluginWithStub(s.modelArmorStub)
	text := armorPlain(chunkBytes-3000) + " " + pemLike(3500) + " " + armorPlain(5000)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, text)), nil)

	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
}

// A throttle on the first chunk has nothing of the request's own before it: after
// the one retry it is other traffic and fails open as the provider's load.
func TestAThrottleOnTheFirstChunkOfALongTextFailsOpen(t *testing.T) {
	t.Parallel()
	s := newArmorScript(t, func(_ int, text string) (int, string) {
		if strings.Contains(text, "FIRST-CHUNK-ONLY") {
			return http.StatusTooManyRequests, rpcResourceExhausted
		}
		return http.StatusOK, allowResponse
	})
	p := pluginWithStub(s.modelArmorStub)
	event, span := newStreamEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, "FIRST-CHUNK-ONLY "+armorPlain(300<<10))), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, appplugins.DetailThrottled, data.FailureDetail)
	assert.Equal(t, "availability", data.FailureClass)
	assertPassThrough(t, res, err)
}

// A chunk beside the first in the first round was sent by the same request: a
// throttle that survives the retry is input.
func TestAThrottleOnALaterChunkOfTheFirstRoundIsInput(t *testing.T) {
	t.Parallel()
	s := newArmorScript(t, func(_ int, text string) (int, string) {
		if !strings.Contains(text, "FIRST-CHUNK-ONLY") {
			return http.StatusTooManyRequests, rpcResourceExhausted
		}
		return http.StatusOK, allowResponse
	})
	p := pluginWithStub(s.modelArmorStub)
	event, span := newStreamEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, "FIRST-CHUNK-ONLY "+armorPlain(150<<10))), nil)
	in.Event = event

	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, appplugins.DetailThrottledOversize, data.FailureDetail)
}

func TestAThrottleOnASingleChunkIsRetriedOnceAndFailsOpen(t *testing.T) {
	t.Parallel()
	s := newArmorScript(t, func(int, string) (int, string) { return http.StatusTooManyRequests, rpcResourceExhausted })
	p := pluginWithStub(s.modelArmorStub)
	event, span := newStreamEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, "hello")), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, appplugins.DetailThrottled, data.FailureDetail)
	assert.Equal(t, "availability", data.FailureClass)
	assert.Len(t, s.sent(), 2)
}

func TestAThrottleThatSucceedsOnRetryGivesTheNormalVerdict(t *testing.T) {
	t.Parallel()
	s := newArmorScript(t, func(call int, _ string) (int, string) {
		if call == 1 {
			return http.StatusTooManyRequests, rpcResourceExhausted
		}
		return http.StatusOK, allowResponse
	})
	p := pluginWithStub(s.modelArmorStub)
	event, span := newStreamEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, armorPlain(150<<10))), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "allowed", data.Decision)
	assert.Empty(t, data.FailureDetail)
}

// Every call hangs past the budget: Model Armor is slow or down, so the chunks that
// never started are not the request's size and the request fails open.
func TestEveryCallHangingPastTheBudgetFailsOpen(t *testing.T) {
	t.Parallel()
	s := newArmorScript(t, func(int, string) (int, string) {
		time.Sleep(1500 * time.Millisecond)
		return http.StatusOK, allowResponse
	})
	p := pluginWithStub(s.modelArmorStub)
	p.clients = &clientCache{build: func(modelArmorCredentials) (*client, error) {
		return newClientWithTokenSource(s.server.URL, 800*time.Millisecond, staticTokenSource("test-token", nil)), nil
	}}
	event, span := newStreamEvent()
	text := armorPlain(300 << 10)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, text)), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "availability", data.FailureClass)
	assert.Equal(t, appplugins.DecisionFailedOpen, data.Decision)
}
