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
	"net/http"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// The answers Model Armor gives when the content kept a filter from running, in
// the shapes Google documents: the quotas page says that above a filter's token
// limit "the filter returns EXECUTION_SKIPPED and includes `Detection skipped as
// token limit exceeded.`", and the SanitizationResult reference puts that text in
// the filter result's messageItems. Whether a skip also turns invocationResult
// into PARTIAL is not documented, so both are exercised.
const (
	skippedPI = `"pi_and_jailbreak":{"piAndJailbreakFilterResult":{"executionState":"EXECUTION_SKIPPED","matchState":"NO_MATCH_FOUND",` +
		`"messageItems":[{"messageType":"INFO","message":"Detection skipped as token limit exceeded."}]}}`
	skippedRAI = `"rai":{"raiFilterResult":{"executionState":"EXECUTION_SKIPPED","matchState":"NO_MATCH_FOUND"}}`

	tokenLimitSkipResponse = `{"sanitizationResult":{"filterMatchState":"NO_MATCH_FOUND","invocationResult":"SUCCESS","filterResults":{` +
		noMatchSDP + `,` + skippedRAI + `,` + skippedPI + `,` + noMatchURIs + `,` + noMatchCSAM + `}}}`
	partialWithSkipResponse = `{"sanitizationResult":{"filterMatchState":"NO_MATCH_FOUND","invocationResult":"PARTIAL","filterResults":{` +
		noMatchSDP + `,` + skippedRAI + `,` + skippedPI + `,` + noMatchURIs + `,` + noMatchCSAM + `}}}`
	partialAllRanResponse = `{"sanitizationResult":{"filterMatchState":"NO_MATCH_FOUND","invocationResult":"PARTIAL","filterResults":{` +
		noMatchSDP + `,` + noMatchNonSDP + `}}}`
)

// A mode that blocks refuses the content a filter was skipped on; observe only
// records it. A template that never enabled the filter, a failed invocation and a
// plain provider error are the customer's or the provider's, and fail open.
func TestExecuteSkippedFilterByClass(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		body   string
		reason string
		detail string
		input  bool
	}{
		{"token limit skip", tokenLimitSkipResponse, "verdict_incomplete", reasonFilterNotExecuted, true},
		{"partial with a skipped filter", partialWithSkipResponse, "verdict_incomplete", reasonFilterNotExecuted, true},
		{"partial with every block_on filter run", partialAllRanResponse, "verdict_incomplete", appplugins.DetailInvocationPartial, false},
		{"filter absent from the template", sdpOnlyAllow, "verdict_incomplete", reasonFilterNotInTemplate, false},
		{"invocation failure", invocationFailureResponse, "transport", "", false},
	} {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(tc.name+" "+string(mode), func(t *testing.T) {
				t.Parallel()
				p := pluginWithStub(newModelArmorStub(t, http.StatusOK, tc.body))
				event, span := newStreamEvent()
				in := execInput(policy.StagePreRequest, mode, modelArmorSettings(), reqCtx(openAIRequest()), nil)
				in.Event = event

				res, err := p.Execute(context.Background(), in)

				wantDecision, wantClass, refused := "failed_open", "availability", false
				if tc.input {
					wantClass = "input"
					if mode == policy.ModeEnforce {
						wantDecision, refused = "failed_closed", true
					}
				}
				if refused {
					pe, ok := appplugins.AsPluginError(err)
					if !ok || pe.StatusCode != http.StatusForbidden || pe.Type != appplugins.TypeGuardrailInputUninspectable {
						t.Fatalf("want a 403 guardrail_input_uninspectable, got res=%+v err=%v", res, err)
					}
				} else {
					assertPassThrough(t, res, err)
				}
				data, ok := span.PluginAttrsCopy().Extras.(*Data)
				if !ok || data.Decision != wantDecision || data.FailureClass != wantClass ||
					data.FailureReason != tc.reason || data.FailureDetail != tc.detail {
					t.Fatalf("extras = %+v, ok=%v, want %s %s/%s class %s", data, ok, wantDecision, tc.reason, tc.detail, wantClass)
				}
			})
		}
	}
}

// A skipped filter in the response outranks a template gap: the skipped one is
// the filter a request can cause, so it is the one named and the one that blocks.
func TestExecuteSkippedFilterOutranksAnAbsentOne(t *testing.T) {
	t.Parallel()
	body := `{"sanitizationResult":{"invocationResult":"SUCCESS","filterResults":{` + noMatchSDP + `,` + skippedPI + `}}}`
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, body))

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	_, err := p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	if !ok || pe.Type != appplugins.TypeGuardrailInputUninspectable {
		t.Fatalf("want a 403 guardrail_input_uninspectable, got %v", err)
	}
}

// A filter that skipped for size does not stop a match elsewhere from being the
// verdict: a real finding is named and blocks.
func TestExecuteMatchWinsOverASkippedFilter(t *testing.T) {
	t.Parallel()
	body := `{"sanitizationResult":{"invocationResult":"PARTIAL","filterResults":{` + matchRAI + `,` + skippedPI + `}}}`
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, body))

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	_, err := p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	if !ok || pe.Type != typeModelArmorBlocked {
		t.Fatalf("expected a Model Armor block, got %v", err)
	}
}

// A usable mask does not rescue a skipped filter: the other filters did not judge
// this content, so a mode that blocks refuses it instead of masking. This is the
// reverse of a template gap, which keeps its mask.
func TestExecuteSkippedFilterBeatsAUsableMaskInEnforce(t *testing.T) {
	t.Parallel()
	body := sanitizeOpen +
		`"sdp":{"sdpFilterResult":{"deidentifyResult":{"matchState":"MATCH_FOUND","infoTypes":["EMAIL_ADDRESS"],"data":{"text":"hello {EMAIL}"}}}},` +
		skippedPI + `,` + noMatchRAI + `,` + noMatchURIs + `,` + noMatchCSAM + sanitizeClose
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, body))
	event, span := newStreamEvent()
	settings := modelArmorSettings()
	settings["sdp_action"] = sdpActionAnonymize
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings, reqCtx(openAIRequest()), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	if !ok || pe.Type != appplugins.TypeGuardrailInputUninspectable || res != nil {
		t.Fatalf("want a 403 guardrail_input_uninspectable and no mask, got res=%+v err=%v", res, err)
	}
	data, _ := span.PluginAttrsCopy().Extras.(*Data)
	if data == nil || data.Decision != "failed_closed" || data.FailureDetail != reasonFilterNotExecuted {
		t.Fatalf("extras = %+v, want failed_closed/%s", data, reasonFilterNotExecuted)
	}
}

// The prompt that rides along with a response is context, not content: padded, it
// would push the response call over the filters' token limit and make them skip.
func TestCorrelationPromptIsBoundedOnARuneBoundary(t *testing.T) {
	t.Parallel()
	if got := tailOnRuneBoundary("short", maxCorrelationPromptBytes); got != "short" {
		t.Fatalf("a short prompt must be kept whole, got %q", got)
	}
	padded := strings.Repeat("é", maxCorrelationPromptBytes) + "THE END"
	got := tailOnRuneBoundary(padded, maxCorrelationPromptBytes)
	if len(got) > maxCorrelationPromptBytes {
		t.Fatalf("len = %d, want at most %d", len(got), maxCorrelationPromptBytes)
	}
	if !strings.HasSuffix(got, "THE END") {
		t.Fatalf("the tail must be kept, got %q", got[len(got)-20:])
	}
	if got[0] != 0xC3 { // first byte of a two-byte rune, never a continuation byte
		t.Fatalf("the cut must land on a rune start, got byte %#x", got[0])
	}
}

func TestCorrelationPromptReachesTheResponseCallBounded(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, allowResponse)
	p := pluginWithStub(stub)
	padding := strings.Repeat("x", 10*maxCorrelationPromptBytes)
	req := reqCtx([]byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"` + padding + `END"}]}`))

	in := execInput(policy.StagePreResponse, policy.ModeEnforce, modelArmorSettings(), req, respCtx(openAIResponse(), false))
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)

	stub.mu.Lock()
	body := string(stub.lastBody)
	stub.mu.Unlock()
	if !strings.Contains(body, "END") {
		t.Fatalf("the end of the prompt is the context that is kept, body = %.80s", body)
	}
	if len(body) > maxCorrelationPromptBytes+2048 {
		t.Fatalf("the request carried %d bytes, the prompt must be bounded", len(body))
	}
}

// On the stream a skipped filter, or an invocation that came back PARTIAL, cuts in
// a mode that blocks, carrying the failure, even when a usable mask is in hand;
// observe releases the block with the typed error.
func TestInspectSegmentSkippedFilterByClass(t *testing.T) {
	t.Parallel()
	maskAndSkip := sanitizeOpen +
		`"sdp":{"sdpFilterResult":{"deidentifyResult":{"matchState":"MATCH_FOUND","infoTypes":["EMAIL_ADDRESS"],"data":{"text":"write to [EMAIL] soon"}}}},` +
		skippedPI + `,` + noMatchRAI + `,` + noMatchURIs + `,` + noMatchCSAM + sanitizeClose
	for _, tc := range []struct {
		name     string
		body     string
		settings map[string]any
		detail   string
	}{
		{"token limit skip", tokenLimitSkipResponse, streamSettings(nil), reasonFilterNotExecuted},
		{"partial with a skipped filter", partialWithSkipResponse, streamSettings(nil), reasonFilterNotExecuted},
		{"a usable mask beside a skipped filter", maskAndSkip, anonymizeStreamSettings(), reasonFilterNotExecuted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := pluginWithStub(newModelArmorStub(t, http.StatusOK, tc.body))

			got, err := p.InspectSegment(context.Background(),
				streamInput(policy.ModeEnforce, tc.settings, nil), segment(3, "some text"))
			if err != nil || got == nil || !got.Block || got.HasTransform {
				t.Fatalf("enforce: verdict = %+v err = %v, want a cut", got, err)
			}
			if got.Type != appplugins.TypeGuardrailInputUninspectable || got.Failure == nil ||
				got.Failure.Reason != appplugins.FailureVerdictIncomplete || got.Failure.Detail != tc.detail ||
				got.Failure.Class != appplugins.FailureClassInput {
				t.Fatalf("enforce: verdict = %+v, want a failure verdict_incomplete/%s/input", got, tc.detail)
			}

			got, err = p.InspectSegment(context.Background(),
				streamInput(policy.ModeObserve, tc.settings, nil), segment(3, "some text"))
			if err == nil || got != nil {
				t.Fatalf("observe: verdict = %+v err = %v, want the typed error and no cut", got, err)
			}
		})
	}
}

// PARTIAL with every block_on filter run says nothing about what the policy asked:
// it is availability on the stream too, released with the typed error in any mode.
// PARTIAL with a block_on filter not executed is the skipped filter, which blocks.
func TestInspectSegmentPartialWithEveryBlockOnFilterRunFailsOpen(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, partialAllRanResponse))
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		got, err := p.InspectSegment(context.Background(),
			streamInput(mode, streamSettings(nil), nil), segment(3, "some text"))
		if err == nil || got != nil {
			t.Fatalf("%s: verdict = %+v err = %v, want the typed error and no cut", mode, got, err)
		}
	}
	settings := streamSettings(nil)
	settings["block_on"] = []string{filterSDP}
	got, err := pluginWithStub(newModelArmorStub(t, http.StatusOK, partialWithSkipResponse)).InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, settings, nil), segment(3, "some text"))
	if err == nil || got != nil {
		t.Fatalf("PARTIAL whose skipped filters are not in block_on: verdict = %+v err = %v, want fail open", got, err)
	}
}

func TestExecutePartialOnlyBlocksThroughASkippedBlockOnFilter(t *testing.T) {
	t.Parallel()
	settings := modelArmorSettings()
	settings["block_on"] = []string{filterSDP}
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, partialWithSkipResponse))
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings, reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
}

// A text that splits into more chunks than are evaluated is refused as the
// input's before any call: a blocking mode refuses it and observe records it. A
// text of one chunk reaches Model Armor whole.
func TestBufferedLegsRefuseTextAboveTheChunkLimitLocally(t *testing.T) {
	t.Parallel()
	body := func(text string) []byte {
		return []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"` + text + `"}]}`)
	}
	response := func(text string) []byte {
		return []byte(`{"id":"r1","model":"gpt-4o","choices":[{"message":{"role":"assistant","content":"` + text + `"},"finish_reason":"stop"}]}`)
	}
	for _, stage := range []policy.Stage{policy.StagePreRequest, policy.StagePreResponse} {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(string(stage)+" "+string(mode)+" 2 MiB", func(t *testing.T) {
				t.Parallel()
				stub := newModelArmorStub(t, http.StatusOK, allowResponse)
				p := pluginWithStub(stub)
				event, span := newStreamEvent()
				big := strings.Repeat("a", 2<<20)
				var in appplugins.ExecInput
				if stage == policy.StagePreRequest {
					in = execInput(stage, mode, modelArmorSettings(), reqCtx(body(big)), nil)
				} else {
					in = execInput(stage, mode, modelArmorSettings(), reqCtx(body("hi")), respCtx(response(big), false))
				}
				in.Event = event

				res, err := p.Execute(context.Background(), in)

				wantDecision := "failed_open"
				if mode == policy.ModeEnforce {
					wantDecision = "failed_closed"
					pe, ok := appplugins.AsPluginError(err)
					if !ok || pe.StatusCode != http.StatusForbidden || pe.Type != appplugins.TypeGuardrailInputUninspectable {
						t.Fatalf("want a 403 guardrail_input_uninspectable, got res=%+v err=%v", res, err)
					}
				} else {
					assertPassThrough(t, res, err)
				}
				if stub.count() != 0 {
					t.Fatalf("an oversize text reached Model Armor %d times", stub.count())
				}
				data, ok := span.PluginAttrsCopy().Extras.(*Data)
				if !ok || data.Decision != wantDecision || data.FailureClass != "input" ||
					data.FailureReason != string(appplugins.FailureInputTooLarge) || data.FailureDetail != appplugins.DetailChunkLimit {
					t.Fatalf("extras = %+v, ok=%v", data, ok)
				}
			})
			t.Run(string(stage)+" "+string(mode)+" one chunk", func(t *testing.T) {
				t.Parallel()
				stub := newModelArmorStub(t, http.StatusOK, allowResponse)
				p := pluginWithStub(stub)
				text := strings.Repeat("a", chunkBytes)
				var in appplugins.ExecInput
				if stage == policy.StagePreRequest {
					in = execInput(stage, mode, modelArmorSettings(), reqCtx(body(text)), nil)
				} else {
					in = execInput(stage, mode, modelArmorSettings(), reqCtx(body("hi")), respCtx(response(text), false))
				}

				res, err := p.Execute(context.Background(), in)

				assertPassThrough(t, res, err)
				if stub.count() != 1 || !strings.Contains(string(stub.lastBody), text) {
					t.Fatalf("want the whole text in one call, got %d calls", stub.count())
				}
			})
		}
	}
}
