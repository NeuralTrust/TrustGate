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

package bedrockguardrail

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

func TestStreamedResponseRecordsSkipWhenStreamingIsNotEnabled(t *testing.T) {
	t.Parallel()
	off, on := map[string]any{"enabled": false}, map[string]any{"enabled": true}
	tests := []struct {
		name      string
		streaming map[string]any
		hasKey    bool
		body      []byte
		streamed  bool
		wantSkip  bool
	}{
		{"streaming key absent: opt-in, so skipped", nil, false, openAIResponse(), true, true},
		{"streaming key absent and no buffered body", nil, false, nil, true, true},
		{"explicitly disabled", off, true, openAIResponse(), true, true},
		{"tuning keys only", map[string]any{"head_chars": 100}, true, openAIResponse(), true, true},
		{"enabled: the stream guard inspects it", on, true, openAIResponse(), true, false},
		{"not streamed: the buffered run inspects it", nil, false, openAIResponse(), false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := &recordingClient{output: allowOutput()}
			p := pluginWith(client)
			set := bedrockSettings(piiActionBlock)
			if tt.hasKey {
				set["streaming"] = tt.streaming
			}
			event, rt, span := skipEvent()
			in := execInput(policy.StagePreResponse, policy.ModeEnforce, set, reqCtx(openAIRequest()), respCtx(tt.body, tt.streamed))
			in.Event = event

			res, err := p.Execute(context.Background(), in)

			assertPassThrough(t, res, err)
			if tt.wantSkip {
				assert.JSONEq(t, skipMarkerJSON, extrasJSON(t, span))
				assertSurvivesIntoPolicyChain(t, rt)
			} else {
				assert.NotContains(t, extrasJSON(t, span), "streaming_disabled")
			}
		})
	}
}

func TestStreamedResponseSkipIsOnlyOnTheResponseLeg(t *testing.T) {
	t.Parallel()
	p := pluginWith(&recordingClient{output: allowOutput()})
	event, _, span := skipEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), respCtx(openAIResponse(), true))
	in.Event = event

	_, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	assert.NotContains(t, extrasJSON(t, span), "streaming_disabled")
}
