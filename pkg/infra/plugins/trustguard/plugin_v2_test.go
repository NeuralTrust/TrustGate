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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// fakeV2Engine is TrustGuard's /v2: its token endpoint and an evaluate endpoint that
// decodes the body as strictly as the engine does (an unknown field, consumer_id or
// agent_id among them, is a 400) and answers with raw.
type fakeV2Engine struct {
	mu            sync.Mutex
	tokens        []map[string]any
	requests      []v2ShadowWireRequest
	headers       []http.Header
	paths         []string
	status        int
	raw           string
	responseFor   map[string]string
	evaluateCalls int32
	invalid       int
	// unauthorizedFirst answers the first evaluate with a 401.
	unauthorizedFirst bool
}

func (f *fakeV2Engine) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.mu.Unlock()
		switch r.URL.Path {
		case v2TokenPath:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.tokens = append(f.tokens, body)
			n := len(f.tokens)
			f.mu.Unlock()
			w.Header().Set("Content-Type", contentTypeJSON)
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "v2-token-" + string(rune('0'+n)), TokenType: "Bearer", ExpiresIn: 3600})
		case v2EvaluatePath:
			calls := atomic.AddInt32(&f.evaluateCalls, 1)
			if f.unauthorizedFirst && calls == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			var body v2ShadowWireRequest
			if err := dec.Decode(&body); err != nil {
				f.mu.Lock()
				f.invalid++
				f.mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.mu.Lock()
			f.requests = append(f.requests, body)
			f.headers = append(f.headers, r.Header.Clone())
			raw := f.raw
			if r, ok := f.responseFor[body.Direction]; ok {
				raw = r
			}
			status := f.status
			f.mu.Unlock()
			if raw == "" {
				raw = `{"status":"allow","transformed_payload":null,"findings":[]}`
			}
			if status == 0 {
				status = http.StatusOK
			}
			w.Header().Set("Content-Type", contentTypeJSON)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(raw))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func (f *fakeV2Engine) seen() []v2ShadowWireRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]v2ShadowWireRequest(nil), f.requests...)
}

func (f *fakeV2Engine) tokenRequests() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.tokens...)
}

func newV2Engine(t *testing.T, f *fakeV2Engine) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return srv
}

func newV2TestPlugin(t *testing.T, baseURL string) *Plugin {
	t.Helper()
	return NewV2(adapter.NewRegistry(), baseURL, testTimeout, "test-v2-client", "test-v2-secret", nil, withBaseTransport(testTransport(t)))
}

func v2Settings(direction string) map[string]any {
	s := map[string]any{}
	if direction != "" {
		s["direction"] = direction
	}
	return s
}

const (
	v2BlockAnswer = `{"status":"block","transformed_payload":null,"trace_id":"t-1","request_id":"r-1","findings":[` +
		`{"source":{"kind":"control","plugin":"prompt_guard","control_id":"0b1c0a5e-7d0e-4b57-8e43-6f3f7e0d4d11","control_name":"Customer secret name","control_scope":"guard","asset_id":"9f2d0e55-5d3d-4c55-9a1a-2f5f1f3c7a10"},` +
		`"signal":{"type":"jailbreak","confidence":0.97},"outcome":{"action":"block"}}]}`
	v2TransformAnswer = `{"status":"transform","transformed_payload":{"input":"be safe\nhello [MASKED_EMAIL]"},"trace_id":"t-2","request_id":"r-2","findings":[` +
		`{"source":{"kind":"control","plugin":"data_loss_prevention","control_id":"0b1c0a5e-7d0e-4b57-8e43-6f3f7e0d4d12","control_scope":"tenant"},` +
		`"signal":{"type":"email","confidence":1},"outcome":{"action":"transform"}}]}`
)

func TestV2PluginIdentity(t *testing.T) {
	t.Parallel()
	p := newV2TestPlugin(t, "http://unused")
	assert.Equal(t, "trustguard_v2", p.Name())
	assert.Equal(t, "trustguard", newTestPlugin(t, adapter.NewRegistry(), "http://unused").Name())
	assert.Nil(t, p.v2Shadow, "trustguard_v2 is the evaluation, it copies nothing")
	assert.Equal(t, newTestPlugin(t, adapter.NewRegistry(), "http://unused").SupportedStages(), p.SupportedStages())
	assert.Equal(t, newTestPlugin(t, adapter.NewRegistry(), "http://unused").SupportedProtocols(), p.SupportedProtocols())
	assert.True(t, p.MutatesRequestBody())
	assert.True(t, p.MutatesResponseBody())
}

func TestV2PluginSpeaksV2OnTheWire(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)

	res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), requestContext(), nil))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Equal(t, []string{v2TokenPath, v2EvaluatePath}, f.paths, "token on /v2/token, evaluation on /v2/evaluate, nothing on /v1")
	require.Len(t, f.tokens, 1)
	assert.Equal(t, "test-v2-client", f.tokens[0]["client_id"])
	assert.Equal(t, "test-v2-secret", f.tokens[0]["client_secret"])
	assert.Equal(t, "platform", f.tokens[0]["scope"])
	assert.Equal(t, "gw-test", f.tokens[0]["gateway_id"])
	assert.NotContains(t, f.tokens[0], "integration_id", "no collector_id configured: TrustGuard resolves it from the gateway")
	assert.NotContains(t, f.tokens[0], "collector_id")

	require.Zero(t, f.invalid, "the engine decodes strictly")
	require.Len(t, f.requests, 1)
	got := f.requests[0]
	assert.Equal(t, "consumer-9", got.ApplicationID)
	assert.Equal(t, "gw-test", got.GatewayID)
	assert.Equal(t, directionInput, got.Direction)
	assert.Equal(t, protocolLLM, got.Protocol)
	assert.Equal(t, "sess-123", got.SessionID)
	assert.Equal(t, map[string]any{"name": "gpt-4o", "provider": "openai", "requested_name": "gpt-4o-mini"}, got.Attributes["model"])
	assert.Equal(t, "Bearer v2-token-1", f.headers[0].Get("Authorization"))
	assert.Equal(t, failureModeOpen, f.headers[0].Get(failureModeHeader))
	assert.NotEmpty(t, f.headers[0].Get(evaluateTimeoutHeader))
	assertLLMRequestMessages(t, got.Payload, []string{"system", "user"}, []string{"be safe", "hello world"})
}

func TestV2PluginTokenNamesTheConfiguredIntegration(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
	require.NoError(t, err)
	tokens := f.tokenRequests()
	require.Len(t, tokens, 1)
	assert.Equal(t, testCollectorID, tokens[0]["integration_id"])
	assert.NotContains(t, tokens[0], "collector_id")
}

func TestV2PluginBlockReturns403(t *testing.T) {
	t.Parallel()
	for _, direction := range []string{directionInput, directionOutput} {
		t.Run(direction, func(t *testing.T) {
			t.Parallel()
			f := &fakeV2Engine{raw: v2BlockAnswer}
			p := newV2TestPlugin(t, newV2Engine(t, f).URL)
			stage, resp := policy.StagePreRequest, (*infracontext.ResponseContext)(nil)
			if direction == directionOutput {
				stage, resp = policy.StagePreResponse, &infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseBody()}
			}

			res, err := p.Execute(context.Background(), execInput(stage, policy.ModeEnforce, v2Settings(""), requestContext(), resp))
			assert.Nil(t, res)
			pe, ok := appplugins.AsPluginError(err)
			require.True(t, ok, "got %v", err)
			assert.Equal(t, http.StatusForbidden, pe.StatusCode)
			assert.Equal(t, typeBlocked, pe.Type)
			assert.Equal(t, direction, blockDirectionOf(t, pe.Body))
			assert.NotContains(t, string(pe.Body), "Customer secret name", "a control's own name never reaches the client")
			assert.Contains(t, string(pe.Body), "jailbreak")
		})
	}
}

func TestV2PluginEnforcementByMode(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		status string
		mode   policy.Mode
		block  bool
	}{
		"block enforce":  {status: statusBlock, mode: policy.ModeEnforce, block: true},
		"block observe":  {status: statusBlock, mode: policy.ModeObserve},
		"ask enforce":    {status: statusAsk, mode: policy.ModeEnforce, block: true},
		"ask observe":    {status: statusAsk, mode: policy.ModeObserve},
		"report enforce": {status: statusReport, mode: policy.ModeEnforce},
		"skip enforce":   {status: statusSkip, mode: policy.ModeEnforce},
		"allow enforce":  {status: statusAllow, mode: policy.ModeEnforce},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := &fakeV2Engine{raw: `{"status":"` + tc.status + `","transformed_payload":null,"findings":[]}`}
			p := newV2TestPlugin(t, newV2Engine(t, f).URL)
			res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, tc.mode, v2Settings(""), requestContext(), nil))
			if tc.block {
				pe, ok := appplugins.AsPluginError(err)
				require.True(t, ok, "got %v", err)
				assert.Equal(t, http.StatusForbidden, pe.StatusCode)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, http.StatusOK, res.StatusCode)
		})
	}
}

func TestV2PluginShadowTenantAnswerIsAllowed(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{raw: `{"status":"allow","shadow_status":"block","shadow":true,"transformed_payload":null,"findings":[` +
		`{"source":{"kind":"control","plugin":"prompt_guard"},"signal":{"type":"jailbreak"},"outcome":{"action":"report"},"shadow_action":"block"}]}`}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)

	res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), requestContext(), nil))
	require.NoError(t, err, "a shadow tenant answers allow; only the verdict it would have given says block")
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestV2PluginTransformRewritesBody(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{raw: v2TransformAnswer}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)

	event, span := newEvent()
	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), requestContext(), nil, event))
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.RequestBody)
	assert.Contains(t, string(res.RequestBody), "hello [MASKED_EMAIL]")
	assert.NotContains(t, string(res.RequestBody), "hello world")
	assert.Equal(t, decisionTransformed, span.PluginAttrsCopy().Decision)

	res, err = p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeObserve, v2Settings(""), requestContext(), nil))
	require.NoError(t, err)
	assert.Nil(t, res.RequestBody, "observe records the mask and rewrites nothing")
}

func TestV2PluginTransformRewritesTheResponse(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{raw: `{"status":"transform","transformed_payload":{"input":"the [MASKED_PII]"},"findings":[]}`}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)

	resp := &infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseBody()}
	res, err := p.Execute(context.Background(), execInput(policy.StagePreResponse, policy.ModeEnforce, v2Settings(""), requestContext(), resp))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Contains(t, string(res.Body), "the [MASKED_PII]")
	seen := f.seen()
	require.Len(t, seen, 1)
	assert.Equal(t, directionOutput, seen[0].Direction)
}

func TestV2PluginMCP(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{raw: v2BlockAnswer}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)
	req := mcpRequestContext()
	req.MCPServerID = "reg-1"
	req.MCPServerCode = "com.asana/mcp"
	req.MCPTool = "create_task"

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), req, nil))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)

	seen := f.seen()
	require.Len(t, seen, 1)
	assert.Equal(t, protocolMCP, seen[0].Protocol)
	assert.Equal(t, "consumer-mcp", seen[0].ApplicationID)
	assert.Equal(t, map[string]any{"id": "com.asana/mcp", "tool": map[string]any{"name": "create_task"}}, seen[0].Attributes["mcp_server"])
	assert.NotContains(t, seen[0].Attributes, "model", "an MCP call names no model")
}

func TestV2PluginSkipsA2A(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)
	req := requestContext()
	req.ConsumerType = protocolA2A

	event, span := newEvent()
	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), req, nil, event))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Zero(t, atomic.LoadInt32(&f.evaluateCalls), "/v2 has no a2a; it would answer 400")
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.True(t, extras.Skipped)
	assert.Equal(t, skipReasonUnsupportedProtocol, extras.SkipReason)
}

func TestV2PluginFailureModes(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			f := &fakeV2Engine{status: status}
			p := newV2TestPlugin(t, newV2Engine(t, f).URL)

			event, span := newEvent()
			res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), requestContext(), nil, event))
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.StatusCode)
			attrs := span.PluginAttrsCopy()
			assert.Equal(t, decisionFailedOpen, attrs.Decision)

			closed := v2Settings("")
			closed["failure_mode"] = failureModeClosed
			_, err = p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, closed, requestContext(), nil))
			pe, ok := appplugins.AsPluginError(err)
			require.True(t, ok, "closed refuses what it could not evaluate, got %v", err)
			assert.Equal(t, http.StatusForbidden, pe.StatusCode)
			assert.Equal(t, failureModeClosed, f.lastFailureMode())

			res, err = p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeObserve, closed, requestContext(), nil))
			require.NoError(t, err, "observe records the failure and forwards")
			assert.Equal(t, http.StatusOK, res.StatusCode)
		})
	}
}

func (f *fakeV2Engine) lastFailureMode() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.headers) == 0 {
		return ""
	}
	return f.headers[len(f.headers)-1].Get(failureModeHeader)
}

func TestV2PluginRateLimitedIsNotAFailure(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{status: http.StatusTooManyRequests, raw: `{"error":"rate limit exceeded"}`}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), requestContext(), nil))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusTooManyRequests, pe.StatusCode)
}

func TestV2PluginRetriesOnceOn401(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{unauthorizedFirst: true}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)

	res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), requestContext(), nil))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.EqualValues(t, 2, atomic.LoadInt32(&f.evaluateCalls))
	assert.Len(t, f.tokenRequests(), 2, "the 401 refreshes the token from /v2/token")
	seen := f.seen()
	require.Len(t, seen, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Equal(t, "Bearer v2-token-2", f.headers[0].Get("Authorization"))
}

func TestV2PluginDirectionSelectsLegs(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)

	_, err := p.Execute(context.Background(), execInput(policy.StagePreResponse, policy.ModeEnforce, v2Settings(legRequest), requestContext(),
		&infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseBody()}))
	require.NoError(t, err)
	assert.Zero(t, atomic.LoadInt32(&f.evaluateCalls))

	_, err = p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, v2Settings(legRequest), requestContext(), nil))
	require.NoError(t, err)
	assert.EqualValues(t, 1, atomic.LoadInt32(&f.evaluateCalls))
}

func TestV2PluginStreamedBlocks(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{raw: v2BlockAnswer}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)
	ctx := segmentTraceContext()
	in := segmentInput(t, v2Settings(legResponse))

	verdict, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{StreamID: "s-1", Seq: 1, Accumulated: "Hello wor"})
	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.True(t, verdict.Block, "a block on a streamed block cuts the stream")
	assert.Equal(t, typeBlocked, verdict.Type)

	seen := f.seen()
	require.Len(t, seen, 1)
	require.Zero(t, f.invalid)
	assert.Equal(t, directionOutput, seen[0].Direction)
	assert.Equal(t, "consumer-9", seen[0].ApplicationID)
	stream, ok := seen[0].Attributes["stream"].(map[string]any)
	require.True(t, ok, "the stream envelope travels in attributes.stream")
	assert.Equal(t, float64(1), stream["seq"])
	assert.Equal(t, []string{v2TokenPath, v2EvaluatePath}, f.pathsSnapshot())
}

func (f *fakeV2Engine) pathsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func TestV2PluginStreamedAllowAndFailOpen(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)
	verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, v2Settings(legResponse)),
		appplugins.StreamSegment{StreamID: "s-2", Seq: 1, Accumulated: "Hello"})
	require.NoError(t, err)
	assert.False(t, verdict.Block)

	broken := &fakeV2Engine{status: http.StatusInternalServerError}
	p = newV2TestPlugin(t, newV2Engine(t, broken).URL)
	verdict, err = p.InspectSegment(segmentTraceContext(), segmentInput(t, v2Settings(legResponse)),
		appplugins.StreamSegment{StreamID: "s-3", Seq: 1, Accumulated: "Hello"})
	require.NoError(t, err)
	assert.False(t, verdict.Block, "failure_mode open lets a block TrustGuard could not evaluate through")

	closed := v2Settings(legResponse)
	closed["failure_mode"] = failureModeClosed
	verdict, err = p.InspectSegment(segmentTraceContext(), segmentInput(t, closed),
		appplugins.StreamSegment{StreamID: "s-4", Seq: 1, Accumulated: "Hello"})
	require.NoError(t, err)
	assert.True(t, verdict.Block, "failure_mode closed cuts the stream")
}

func TestV2PluginStreamSkipsA2A(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{raw: v2BlockAnswer}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)
	in := segmentInput(t, v2Settings(legResponse))
	in.Request.ConsumerType = protocolA2A

	verdict, err := p.InspectSegment(segmentTraceContext(), in, appplugins.StreamSegment{StreamID: "s-5", Seq: 1, Accumulated: "Hello"})
	require.NoError(t, err)
	assert.False(t, verdict.Block)
	assert.Zero(t, atomic.LoadInt32(&f.evaluateCalls))
}

func TestV2PluginFindingsAreDeduplicatedByTheirV2Ids(t *testing.T) {
	t.Parallel()
	var resp GuardResponse
	require.NoError(t, json.Unmarshal([]byte(v2BlockAnswer), &resp))
	normalizeV2Response(&resp)
	require.Len(t, resp.Findings, 1)
	src := resp.Findings[0].Source
	assert.Equal(t, "0b1c0a5e-7d0e-4b57-8e43-6f3f7e0d4d11", src.DetectorID)
	assert.Equal(t, "Customer secret name", src.ControlName)
	assert.Empty(t, src.DetectorName)
	assert.Equal(t, "9f2d0e55-5d3d-4c55-9a1a-2f5f1f3c7a10", src.AssetID)

	other := GuardFinding{Source: &GuardFindingSource{Kind: "exception", ExceptionID: "e-1"}}
	killSwitch := GuardFinding{Source: &GuardFindingSource{Kind: "kill_switch", AssetID: "a-1"}}
	resp = GuardResponse{Findings: []GuardFinding{other, killSwitch}}
	normalizeV2Response(&resp)
	assert.Equal(t, "e-1", resp.Findings[0].Source.DetectorID)
	assert.Equal(t, "a-1", resp.Findings[1].Source.DetectorID)
	normalizeV2Response(nil)
}

func TestV2PluginConfig(t *testing.T) {
	t.Parallel()
	p := newV2TestPlugin(t, "http://unused")

	t.Run("collector_id is optional", func(t *testing.T) {
		require.NoError(t, p.ValidateConfig(map[string]any{}))
		require.NoError(t, p.ValidateConfig(map[string]any{"direction": legRequest, "failure_mode": failureModeClosed}))
		require.NoError(t, p.ValidateConfig(settings("")))
	})
	t.Run("collector_id is required by v1", func(t *testing.T) {
		v1 := newTestPlugin(t, adapter.NewRegistry(), "http://unused")
		require.Error(t, v1.ValidateConfig(map[string]any{}))
	})
	t.Run("a collector_id given must be a UUID", func(t *testing.T) {
		err := p.ValidateConfig(map[string]any{"collector_id": "not-a-uuid"})
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "trustguard_v2:"), err.Error())
	})
	t.Run("same keys, same validation as v1", func(t *testing.T) {
		require.Error(t, p.ValidateConfig(map[string]any{"direction": "sideways"}))
		require.Error(t, p.ValidateConfig(map[string]any{"failure_mode": "sometimes"}))
		require.Error(t, p.ValidateConfig(map[string]any{"streaming": map[string]any{"head_chars": -1}}))
	})
	t.Run("credentials are required", func(t *testing.T) {
		noCreds := NewV2(adapter.NewRegistry(), "http://unused", testTimeout, "", "", nil)
		err := noCreds.ValidateConfig(map[string]any{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TRUSTGUARD_V2_CLIENT_ID")
	})
}

func TestV2PluginWithoutCredentialsOrBaseURLFailsOpenWithoutACall(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{}
	srv := newV2Engine(t, f)

	noCreds := NewV2(adapter.NewRegistry(), srv.URL, testTimeout, "", "", nil, withBaseTransport(testTransport(t)))
	event, span := newEvent()
	res, err := noCreds.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), requestContext(), nil, event))
	require.NoError(t, err)
	assertFailedOpen(t, res, span, failureReasonCredentialsMissing)

	noURL := newV2TestPlugin(t, "")
	event, span = newEvent()
	res, err = noURL.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), requestContext(), nil, event))
	require.NoError(t, err)
	assertFailedOpen(t, res, span, failureReasonBaseURLMissing)
	assert.Zero(t, atomic.LoadInt32(&f.evaluateCalls))
}

func TestV2PluginTimeoutFailsOpen(t *testing.T) {
	t.Parallel()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == v2TokenPath {
			w.Header().Set("Content-Type", contentTypeJSON)
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "t", TokenType: "Bearer", ExpiresIn: 3600})
			return
		}
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(slow.Close)
	p := NewV2(adapter.NewRegistry(), slow.URL, 150*time.Millisecond, "c", "s", nil, withBaseTransport(testTransport(t)))

	event, span := newEvent()
	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), requestContext(), nil, event))
	require.NoError(t, err)
	assertFailedOpen(t, res, span, failureReasonTimeout)
}
