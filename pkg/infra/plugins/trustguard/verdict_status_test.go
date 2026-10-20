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
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// payloadMarker is text that belongs to the inspected payload. A warn for an
// unrecognized status must not carry it.
const payloadMarker = "UNLOGGED_PAYLOAD_zz"

func newLoggingPlugin(t *testing.T, baseURL string, logs *strings.Builder) *Plugin {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return New(adapter.NewRegistry(), baseURL, testTimeout, "test-client", "test-secret", logger, withBaseTransport(testTransport(t)))
}

func requestWithPayloadMarker() *infracontext.RequestContext {
	req := requestContext()
	req.Body = []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"` + payloadMarker + `"}]}`)
	return req
}

// explicitBlockVerdict is what an explicit block with no findings returns, and
// what an unrecognized status returns in a mode that blocks.
func explicitBlockVerdict() appplugins.SegmentVerdict {
	return appplugins.SegmentVerdict{Block: true, Type: typeBlocked, Message: blockMessage}
}

func TestKnownVerdictsUnchangedInBlockingMode(t *testing.T) {
	t.Parallel()

	t.Run("buffered", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name         string
			status       string
			transform    bool
			wantDecision string
			wantBlock    bool
		}{
			{name: "allow", status: statusAllow, wantDecision: decisionAllowed},
			{name: "empty", status: "", wantDecision: decisionAllowed},
			{name: "report", status: statusReport, wantDecision: decisionReported},
			{name: "skip", status: statusSkip, wantDecision: decisionAllowed},
			{name: "error", status: statusError, wantDecision: decisionReported},
			{name: "transform", status: statusTransform, transform: true, wantDecision: decisionTransformed},
			{name: "ask", status: statusAsk, wantDecision: decisionBlocked, wantBlock: true},
			{name: "block", status: statusBlock, wantDecision: decisionBlocked, wantBlock: true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				resp := GuardResponse{Status: tc.status, TraceID: "trace-" + tc.name}
				req := requestWithPayloadMarker()
				if tc.transform {
					resp = transformResponse("be safe\nhello [MASKED_PII]")
					req = requestContext()
				}
				logs, res, decision, err := executeVerdict(t, policy.ModeEnforce, req, resp)
				assert.NotContains(t, logs, unrecognizedStatusLog)
				assert.NotContains(t, logs, payloadMarker)
				assert.NotContains(t, logs, "hello world")
				assert.Equal(t, tc.wantDecision, decision)
				if tc.wantBlock {
					assertExplicitBlock(t, res, err)
					return
				}
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, http.StatusOK, res.StatusCode)
				assert.False(t, res.StopUpstream)
				if tc.transform {
					assert.Contains(t, string(res.RequestBody), "hello [MASKED_PII]")
					assert.NotContains(t, string(res.RequestBody), "hello world")
				}
			})
		}
	})

	t.Run("stream", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name   string
			resp   GuardResponse
			seg    appplugins.StreamSegment
			want   appplugins.SegmentVerdict
			secret string
		}{
			{name: "allow", resp: GuardResponse{Status: statusAllow}, want: appplugins.SegmentVerdict{}, secret: payloadMarker},
			{name: "empty", resp: GuardResponse{}, want: appplugins.SegmentVerdict{}, secret: payloadMarker},
			{name: "report", resp: GuardResponse{Status: statusReport}, want: appplugins.SegmentVerdict{}, secret: payloadMarker},
			{name: "skip", resp: GuardResponse{Status: statusSkip}, want: appplugins.SegmentVerdict{}, secret: payloadMarker},
			{name: "error", resp: GuardResponse{Status: statusError}, want: appplugins.SegmentVerdict{}, secret: payloadMarker},
			{
				name:   "transform",
				resp:   GuardResponse{Status: statusTransform, TransformedPayload: map[string]any{"input": "Hello [MASKED]"}},
				seg:    appplugins.StreamSegment{Seq: 3, Accumulated: "Hello world"},
				want:   appplugins.SegmentVerdict{HasTransform: true, Transformed: "Hello [MASKED]"},
				secret: "Hello world",
			},
			{name: "ask", resp: GuardResponse{Status: statusAsk}, want: explicitBlockVerdict(), secret: payloadMarker},
			{name: "block", resp: GuardResponse{Status: statusBlock}, want: explicitBlockVerdict(), secret: payloadMarker},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				seg := tc.seg
				if seg.Accumulated == "" {
					seg = appplugins.StreamSegment{Seq: 2, Accumulated: payloadMarker}
				}
				logs, verdict := inspectVerdict(t, policy.ModeEnforce, seg, tc.resp)
				assert.NotContains(t, logs, unrecognizedStatusLog)
				assert.NotContains(t, logs, tc.secret)
				assert.Equal(t, tc.want, *verdict)
			})
		}
	})
}

func TestUnknownStatusBlockingModeBlocksAndWarns(t *testing.T) {
	t.Parallel()

	const unknown = "blok"

	t.Run("buffered", func(t *testing.T) {
		t.Parallel()
		logs, res, decision, err := executeVerdict(t, policy.ModeEnforce, requestWithPayloadMarker(), GuardResponse{Status: unknown})
		assertExplicitBlock(t, res, err)
		assert.Equal(t, decisionBlocked, decision)
		assertUnrecognizedWarn(t, logs, unknown)
		assert.NotContains(t, logs, payloadMarker)
		assertBlockBodyStatus(t, err, statusBlock)
	})

	t.Run("stream", func(t *testing.T) {
		t.Parallel()
		logs, verdict := inspectVerdict(t, policy.ModeEnforce,
			appplugins.StreamSegment{Seq: 4, Accumulated: payloadMarker},
			GuardResponse{Status: unknown})
		assert.Equal(t, explicitBlockVerdict(), *verdict)
		assertUnrecognizedWarn(t, logs, unknown)
		assert.NotContains(t, logs, payloadMarker)
		assert.Contains(t, logs, "seq=4")
	})
}

func TestUnknownStatusNonBlockingModeForwards(t *testing.T) {
	t.Parallel()

	const unknown = "blok"

	t.Run("buffered", func(t *testing.T) {
		t.Parallel()
		logs, res, decision, err := executeVerdict(t, policy.ModeObserve, requestWithPayloadMarker(), GuardResponse{Status: unknown})
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.False(t, res.StopUpstream)
		assert.Empty(t, res.RequestBody)
		assert.Equal(t, decisionReported, decision)
		assert.NotContains(t, logs, unrecognizedStatusLog)
		assert.NotContains(t, logs, payloadMarker)
	})

	t.Run("stream", func(t *testing.T) {
		t.Parallel()
		logs, verdict := inspectVerdict(t, policy.ModeObserve,
			appplugins.StreamSegment{Seq: 4, Accumulated: payloadMarker},
			GuardResponse{Status: unknown})
		assert.Equal(t, appplugins.SegmentVerdict{}, *verdict)
		assert.NotContains(t, logs, unrecognizedStatusLog)
		assert.NotContains(t, logs, payloadMarker)
	})
}

func executeVerdict(t *testing.T, mode policy.Mode, req *infracontext.RequestContext, resp GuardResponse) (string, *appplugins.Result, string, error) {
	t.Helper()
	f := &fakeGuard{response: resp}
	var logs strings.Builder
	p := newLoggingPlugin(t, newServer(t, f).URL, &logs)
	event, span := newEvent()
	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, mode, settings(""), req, nil, event))
	decision := ""
	if extras, ok := span.PluginAttrsCopy().Extras.(guardData); ok {
		decision = extras.Decision
	}
	return logs.String(), res, decision, err
}

func inspectVerdict(t *testing.T, mode policy.Mode, seg appplugins.StreamSegment, resp GuardResponse) (string, *appplugins.SegmentVerdict) {
	t.Helper()
	g := &segmentGuard{response: resp}
	var logs strings.Builder
	p := newLoggingPlugin(t, newSegmentServer(t, g).URL, &logs)
	in := execInput(policy.StagePreResponse, mode, streamingSettings(nil), segmentRequest(), nil)
	verdict, err := p.InspectSegment(segmentTraceContext(), in, seg)
	require.NoError(t, err)
	require.NotNil(t, verdict)
	return logs.String(), verdict
}

func TestUnrecognizedStatusLogIsTruncated(t *testing.T) {
	t.Parallel()

	unknown := "unknown-" + strings.Repeat("x", 80)
	logs, res, decision, err := executeVerdict(t, policy.ModeEnforce, requestWithPayloadMarker(), GuardResponse{Status: unknown})
	assertExplicitBlock(t, res, err)
	assert.Equal(t, decisionBlocked, decision)
	assertBlockBodyStatus(t, err, statusBlock)
	logged := loggedStatus(unknown)
	require.LessOrEqual(t, len(logged), maxLoggedStatusBytes)
	require.NotEqual(t, unknown, logged)
	assert.Contains(t, logs, "status="+logged)
	assert.NotContains(t, logs, unknown)
	assert.NotContains(t, logs, payloadMarker)
}

func assertExplicitBlock(t *testing.T, res *appplugins.Result, err error) {
	t.Helper()
	assert.Nil(t, res)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Equal(t, typeBlocked, pe.Type)
	assert.Equal(t, blockMessage, pe.Message)
}

func assertBlockBodyStatus(t *testing.T, err error, want string) {
	t.Helper()
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	var body struct {
		Status string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(pe.Body, &body))
	assert.Equal(t, want, body.Status)
}

func assertUnrecognizedWarn(t *testing.T, logs, status string) {
	t.Helper()
	assert.Contains(t, logs, "level=WARN")
	assert.Contains(t, logs, unrecognizedStatusLog)
	assert.Contains(t, logs, "status="+status)
}
