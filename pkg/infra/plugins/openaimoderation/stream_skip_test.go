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
		streamed  bool
		wantSkip  bool
	}{
		{"streaming key absent", nil, false, true, true},
		{"explicitly disabled", off, true, true, true},
		{"tuning keys only", map[string]any{"head_chars": 100}, true, true, true},
		{"enabled: the stream guard inspects it", on, true, true, false},
		{"not streamed: the buffered run inspects it", nil, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeModerator{response: flaggedHateResponse()}
			srv := newModeratorServer(t, f)
			p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
			set := blockSettings()
			set["stages"] = []string{"pre_response"}
			if tt.hasKey {
				set["streaming"] = tt.streaming
			}
			resp := responseContext()
			resp.Streaming = tt.streamed
			event, rt, span := skipEvent()

			_, _ = p.Execute(context.Background(), execInput(policy.StagePreResponse, policy.ModeObserve, set, requestContext(), resp, event))

			if tt.wantSkip {
				assert.Equal(t, 0, f.count(), "a skipped stream must not call the moderations API")
				assert.JSONEq(t, skipMarkerJSON, extrasJSON(t, span))
				assertSurvivesIntoPolicyChain(t, rt)
			} else {
				assert.NotContains(t, extrasJSON(t, span), "streaming_disabled")
			}
		})
	}
}

// A policy that does not cover the response leg is not a policy that skipped a
// streamed response: it never meant to look at it.
func TestStreamedResponseSkipIsOnlyOnACoveredResponseLeg(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
	set := blockSettings()
	set["stages"] = []string{"pre_request"}
	resp := responseContext()
	resp.Streaming = true
	event, _, span := skipEvent()

	_, _ = p.Execute(context.Background(), execInput(policy.StagePreResponse, policy.ModeObserve, set, requestContext(), resp, event))

	assert.NotContains(t, extrasJSON(t, span), "streaming_disabled")
}
