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

package trustguard

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const testStreamTraceID = "trace-stream-1"

func openAIToolRequestBody() []byte {
	return []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}],` +
		`"tools":[{"type":"function","function":{"name":"search","description":"look things up",` +
		`"parameters":{"type":"object"}}}]}`)
}

func segmentRequest() *infracontext.RequestContext {
	req := requestContext()
	req.Body = openAIToolRequestBody()
	return req
}

type segmentPayloadBody struct {
	Messages []struct {
		Role      string           `json:"role"`
		Content   *string          `json:"content"`
		Reasoning string           `json:"reasoning_content"`
		ToolCalls []map[string]any `json:"tool_calls"`
	} `json:"messages"`
	Tools []map[string]any `json:"tools"`
}

func TestSegmentStreamID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		traceID string
		seg     appplugins.StreamSegment
		want    string
	}{
		{"the trace id names the response leg", testStreamTraceID,
			appplugins.StreamSegment{StreamID: "guard-handle"}, testStreamTraceID + streamIDSeparator + legResponse},
		{"without a trace the caller handle stands in", "",
			appplugins.StreamSegment{StreamID: "guard-handle"}, "guard-handle"},
		{"no trace and no handle leaves no id", "", appplugins.StreamSegment{}, ""},
		{"a blank handle is not an id", "", appplugins.StreamSegment{StreamID: "   "}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, segmentStreamID(tt.traceID, tt.seg))
		})
	}
}

func TestSegmentPayload(t *testing.T) {
	t.Parallel()

	p := &Plugin{registry: adapter.NewRegistry()}
	in := appplugins.ExecInput{Request: segmentRequest()}

	tests := []struct {
		name          string
		seg           appplugins.StreamSegment
		wantOK        bool
		wantContent   *string
		wantReasoning string
		wantToolCalls int
		wantTools     bool
	}{
		{name: "head block", seg: appplugins.StreamSegment{Seq: 1, Accumulated: "Hel"},
			wantOK: true, wantContent: ptr("Hel")},
		{name: "cumulative prefix with reasoning",
			seg:    appplugins.StreamSegment{Seq: 2, Accumulated: "Hello wor", Reasoning: "weighing it up"},
			wantOK: true, wantContent: ptr("Hello wor"), wantReasoning: "weighing it up"},
		{name: "final block carries tools[]",
			seg: appplugins.StreamSegment{
				Seq: 3, Final: true, Accumulated: "Hello world", Reasoning: "weighing it up",
				ToolCalls: []adapter.CanonicalToolCall{{ID: "call-1", Name: "search", Arguments: `{"q":"x"}`}},
			},
			wantOK: true, wantContent: ptr("Hello world"), wantReasoning: "weighing it up",
			wantToolCalls: 1, wantTools: true},
		{name: "a tool call with no text is still inspectable",
			seg: appplugins.StreamSegment{
				Seq:       4,
				ToolCalls: []adapter.CanonicalToolCall{{ID: "call-1", Name: "search", Arguments: `{"q":"x"}`}},
			},
			wantOK: true, wantToolCalls: 1},
		{name: "reasoning with no text is still inspectable",
			seg:    appplugins.StreamSegment{Seq: 5, Reasoning: "weighing it up"},
			wantOK: true, wantContent: ptr(""), wantReasoning: "weighing it up"},
		{name: "nothing produced yet", seg: appplugins.StreamSegment{Seq: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw, ok := p.segmentPayload(t.Context(), in, tt.seg)
			require.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				assert.Nil(t, raw)
				return
			}

			var payload segmentPayloadBody
			require.NoError(t, json.Unmarshal(raw, &payload))
			require.Len(t, payload.Messages, 1)
			msg := payload.Messages[0]
			assert.Equal(t, "assistant", msg.Role)
			assert.Equal(t, tt.wantContent, msg.Content)
			assert.Equal(t, tt.wantReasoning, msg.Reasoning)
			assert.Len(t, msg.ToolCalls, tt.wantToolCalls)
			if tt.wantTools {
				assert.NotEmpty(t, payload.Tools, "tools[] belongs on the final block")
			} else {
				assert.Empty(t, payload.Tools, "tools[] must be omitted while final is false")
			}
		})
	}
}

func TestRequestTools(t *testing.T) {
	t.Parallel()

	p := &Plugin{registry: adapter.NewRegistry()}

	t.Run("no request", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, p.requestTools(nil))
	})

	t.Run("decoded from the request body", func(t *testing.T) {
		t.Parallel()
		tools := p.requestTools(segmentRequest())
		require.Len(t, tools, 1)
		assert.Equal(t, "search", tools[0].Name)
	})

	t.Run("unsupported format", func(t *testing.T) {
		t.Parallel()
		req := segmentRequest()
		req.Provider = "not-a-provider"
		req.SourceFormat = "not-a-format"
		assert.Nil(t, p.requestTools(req))
	})
}

func TestSegmentVerdicts(t *testing.T) {
	t.Parallel()

	finding := GuardFinding{
		Source:  &GuardFindingSource{Kind: "detector", DetectorName: "Toxicity"},
		Signal:  &GuardFindingSignal{Type: "toxicity", Confidence: 0.9},
		Outcome: &GuardFindingOutcome{Action: "block"},
	}
	produced := appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"}
	toolCallOnly := appplugins.StreamSegment{
		Seq:       1,
		ToolCalls: []adapter.CanonicalToolCall{{ID: "call-1", Name: "search", Arguments: `{"q":"x"}`}},
	}

	tests := []struct {
		name string
		seg  appplugins.StreamSegment
		resp GuardResponse
		want appplugins.SegmentVerdict
	}{
		{"allow", produced, GuardResponse{Status: statusAllow}, appplugins.SegmentVerdict{}},
		{"report never blocks a block", produced,
			GuardResponse{Status: statusReport, Findings: []GuardFinding{finding}},
			appplugins.SegmentVerdict{}},
		{"block", produced, GuardResponse{Status: statusBlock, Findings: []GuardFinding{finding}},
			appplugins.SegmentVerdict{
				Block:   true,
				Type:    typeBlocked,
				Message: "Request blocked by security policy: toxicity (Toxicity).",
			}},
		{"ask blocks like block", produced, GuardResponse{Status: statusAsk}, appplugins.SegmentVerdict{
			Block: true, Type: typeBlocked, Message: blockMessage,
		}},
		{"transform carries the masked buffer", produced,
			GuardResponse{Status: statusTransform, TransformedPayload: map[string]any{"input": "Hello [MASKED]"}},
			appplugins.SegmentVerdict{HasTransform: true, Transformed: "Hello [MASKED]"}},
		{"transform without a payload blocks", produced, GuardResponse{Status: statusTransform},
			appplugins.SegmentVerdict{Block: true, Type: typeBlocked, Message: blockMessage}},
		{"transform with nothing accumulated blocks instead of injecting", toolCallOnly,
			GuardResponse{Status: statusTransform, TransformedPayload: map[string]any{"input": "[MASKED]"}},
			appplugins.SegmentVerdict{Block: true, Type: typeBlocked, Message: blockMessage}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			verdict := segmentVerdict(tt.seg, &tt.resp)
			require.NotNil(t, verdict)
			assert.Equal(t, tt.want, *verdict)
		})
	}
}

func TestSegmentVerdictConstructors(t *testing.T) {
	t.Parallel()

	assert.Equal(t, appplugins.SegmentVerdict{}, *segmentAllow())
	assert.Equal(t, appplugins.SegmentVerdict{Block: true, Type: typeRateLimited, Message: rateLimitMessage},
		*segmentBlock(typeRateLimited, rateLimitMessage))
}

func ptr[T any](v T) *T { return &v }
