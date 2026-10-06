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

package regexreplace

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const skipMarkerJSON = `{"stage":"pre_response","skipped":true,"skip_reason":"streaming_disabled"}`

type skipNoPricing struct{}

func (skipNoPricing) Resolve(context.Context, string, string) appcatalog.Pricing {
	return appcatalog.Pricing{}
}

func (skipNoPricing) InvalidateCache() {}

func skipEvent() (*metrics.EventContext, *trace.RequestTrace, *trace.Span) {
	rt := trace.New("trace-skip", trace.Metadata{GatewayID: "gw-1"})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)
	span.SetStage(string(policy.StagePreResponse))
	span.SetStatusCode(200)
	return metrics.NewEventContext(span), rt, span
}

// extrasJSON is the span's extras as the console reads them; empty when the
// plugin wrote nothing.
func extrasJSON(t *testing.T, span *trace.Span) string {
	t.Helper()
	extras := span.PluginAttrsCopy().Extras
	if extras == nil {
		return ""
	}
	raw, err := json.Marshal(extras)
	require.NoError(t, err)
	return string(raw)
}

// assertSurvivesIntoPolicyChain runs the real metrics builder over the trace:
// the skipped entry must not be dropped as a no-op span.
func assertSurvivesIntoPolicyChain(t *testing.T, rt *trace.RequestTrace) {
	t.Helper()
	evt := appmetrics.NewBuilder(adapter.NewRegistry(), skipNoPricing{}).Build(
		context.Background(), rt,
		&infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"},
		&infracontext.ResponseContext{StatusCode: 200},
		time.UnixMilli(1_000_000), time.UnixMilli(1_000_005),
	)
	require.Len(t, evt.PolicyChain, 1, "a policy that did not inspect a streamed response must stay in the chain")
	entry := evt.PolicyChain[0]
	assert.Equal(t, PluginName, entry.Name)
	assert.Empty(t, entry.Decision)
	assert.False(t, entry.Flagged)
	assert.Equal(t, map[string]any{
		"stage": "pre_response", "skipped": true, "skip_reason": "streaming_disabled",
	}, entry.Extras)
}

func TestStreamedResponseRecordsSkipOnlyWhenStreamingIsDisabled(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		streaming map[string]any
		hasKey    bool
		body      []byte
		streamed  bool
		wantSkip  bool
	}{
		// Unlike the guardrails, absent means on: the stream guard rewrites it.
		{"streaming key absent: the stream guard inspects it", nil, false, openAIResponse("the answer"), true, false},
		{"streaming key absent and no buffered body", nil, false, nil, true, false},
		{"explicitly disabled", map[string]any{"enabled": false}, true, openAIResponse("the answer"), true, true},
		{"explicitly disabled and no buffered body", map[string]any{"enabled": false}, true, nil, true, true},
		{"explicitly enabled", map[string]any{"enabled": true}, true, openAIResponse("the answer"), true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := New(adapter.NewRegistry(), nil)
			set := settings(targetResponse, maskRule("answer", "solution"))
			if tt.hasKey {
				set["streaming"] = tt.streaming
			}
			event, rt, span := skipEvent()
			in := execInput(policy.StagePreResponse, policy.ModeEnforce, set,
				reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "q")), respCtx(tt.body, tt.streamed), event)

			res, err := p.Execute(context.Background(), in)

			assertPassThrough(t, res, err)
			if tt.wantSkip {
				assert.JSONEq(t, skipMarkerJSON, extrasJSON(t, span))
				assertSurvivesIntoPolicyChain(t, rt)
			} else if tt.streamed {
				assert.Empty(t, extrasJSON(t, span), "the stream guard reports an opted-in stream, not the buffered run")
			}
		})
	}
}

// streaming.enabled governs streamed responses only: a buffered one is
// rewritten as ever, and says nothing about streaming.
func TestBufferedResponseIsRewrittenWhateverStreamingSays(t *testing.T) {
	t.Parallel()
	for name, streaming := range map[string]map[string]any{
		"absent":   nil,
		"disabled": {"enabled": false},
		"enabled":  {"enabled": true},
	} {
		p := New(adapter.NewRegistry(), nil)
		set := settings(targetResponse, maskRule("answer", "solution"))
		if streaming != nil {
			set["streaming"] = streaming
		}
		event, _, span := skipEvent()
		in := execInput(policy.StagePreResponse, policy.ModeEnforce, set,
			reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "q")), respCtx(openAIResponse("the answer"), false), event)

		res, err := p.Execute(context.Background(), in)

		require.NoError(t, err, name)
		assert.Contains(t, string(res.Body), "the solution", name)
		assert.NotContains(t, extrasJSON(t, span), "streaming_disabled", name)
	}
}

// A policy that targets the request is not on the response leg, so a streamed
// response is not something it skipped.
func TestStreamedResponseSkipIsOnlyForAPolicyCoveringTheResponse(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := settings(targetRequest, maskRule("answer", "solution"))
	set["streaming"] = map[string]any{"enabled": false}
	event, _, span := skipEvent()
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, set,
		reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "q")), respCtx(openAIResponse("the answer"), true), event)

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	assert.Empty(t, extrasJSON(t, span))
}

// A stored policy whose settings no longer parse already fails every buffered
// run, streamed or not. Streaming being on by default does not add a second
// failure: it is not a stream participant (see StreamSettings), so the guard
// never calls it per block.
func TestStreamedResponseWithUnparseableSettingsFailsAsItAlwaysDid(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := map[string]any{"target": targetResponse, "rules": []map[string]any{{"pattern": "(", "replacement": "x"}}}
	event, _, span := skipEvent()
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, set,
		reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "q")), respCtx(openAIResponse("the answer"), true), event)

	_, err := p.Execute(context.Background(), in)

	require.Error(t, err)
	assert.Empty(t, extrasJSON(t, span))
	joins, _ := p.StreamSettings(set)
	assert.False(t, joins, "an unparseable policy must not join the stream guard")
}
