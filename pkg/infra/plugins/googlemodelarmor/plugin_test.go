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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// modelArmorStub is a minimal HTTP stub standing in for Model Armor's
// regional sanitize endpoints. It always answers with the same canned
// response, which is enough to drive the plugin's decision branches without
// needing real GCP credentials or a real Model Armor template.
type modelArmorStub struct {
	mu       sync.Mutex
	hits     int
	lastPath string
	lastBody []byte
	server   *httptest.Server
}

func newModelArmorStub(t *testing.T, status int, body string) *modelArmorStub {
	t.Helper()
	s := &modelArmorStub{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.hits++
		s.lastPath = r.URL.Path
		s.lastBody = raw
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *modelArmorStub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func (s *modelArmorStub) path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPath
}

func pluginWithStub(s *modelArmorStub) *Plugin {
	return &Plugin{
		registry: adapter.NewRegistry(),
		clients: &clientCache{
			build: func(modelArmorCredentials) (*client, error) {
				return newClientWithTokenSource(s.server.URL, time.Second, staticTokenSource("test-token", nil)), nil
			},
		},
	}
}

// pluginWithClientError builds a plugin whose token source always fails, so
// every sanitize call returns a transport-level error without touching the
// network. It stands in for "the Model Armor call failed" the way bedrock's
// tests use a recordingClient with a static err.
func pluginWithClientError(err error) *Plugin {
	return &Plugin{
		registry: adapter.NewRegistry(),
		clients: &clientCache{
			build: func(modelArmorCredentials) (*client, error) {
				return newClientWithTokenSource("https://example.invalid", time.Second, staticTokenSource("", err)), nil
			},
		},
	}
}

func modelArmorSettings() map[string]any {
	return map[string]any{
		"project":  "proj",
		"location": "us-central1",
		"template": "tmpl-1",
	}
}

func reqCtx(body []byte) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Provider:     "openai",
		SourceFormat: "openai",
		Body:         body,
	}
}

func respCtx(body []byte, streaming bool) *infracontext.ResponseContext {
	return &infracontext.ResponseContext{
		Body:      body,
		Streaming: streaming,
	}
}

func execInput(stage policy.Stage, mode policy.Mode, set map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    stage,
		Mode:     mode,
		Config:   policy.PluginConfig{Settings: set},
		Request:  req,
		Response: resp,
	}
}

func openAIRequest() []byte {
	return []byte(`{"model":"gpt-4o","messages":[{"role":"system","content":"be safe"},{"role":"user","content":"hello world"}]}`)
}

func openAIResponse() []byte {
	return []byte(`{"id":"r1","model":"gpt-4o","choices":[{"message":{"role":"assistant","content":"the answer"},"finish_reason":"stop"}]}`)
}

const (
	allowResponse = `{"sanitizationResult":{"filterMatchState":"NO_MATCH_FOUND","invocationResult":"SUCCESS","filterResults":{}}}`

	raiBlockResponse = `{"sanitizationResult":{"filterMatchState":"MATCH_FOUND","invocationResult":"SUCCESS","filterResults":{` +
		`"rai":{"raiFilterResult":{"matchState":"MATCH_FOUND"}}}}}`

	invocationFailureResponse = `{"sanitizationResult":{"filterMatchState":"NO_MATCH_FOUND","invocationResult":"FAILURE","filterResults":{}}}`
)

func sdpAnonymizeResponse(masked string) string {
	raw, _ := json.Marshal(masked)
	return `{"sanitizationResult":{"filterMatchState":"MATCH_FOUND","invocationResult":"SUCCESS","filterResults":{` +
		`"sdp":{"sdpFilterResult":{"deidentifyResult":{"matchState":"MATCH_FOUND","infoTypes":["EMAIL_ADDRESS"],"data":{"text":` + string(raw) + `}}}}}}}`
}

func assertPassThrough(t *testing.T, res *appplugins.Result, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream || res.Body != nil || res.RequestBody != nil {
		t.Fatalf("expected pass-through, got %+v", res)
	}
}

func TestExecutePreRequestCallsSanitizeUserPrompt(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, allowResponse)
	p := pluginWithStub(stub)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if stub.count() != 1 {
		t.Fatalf("expected one sanitize call, got %d", stub.count())
	}
	if !strings.HasSuffix(stub.path(), ":sanitizeUserPrompt") {
		t.Fatalf("path = %q, want suffix :sanitizeUserPrompt", stub.path())
	}
}

func TestExecutePreResponseCallsSanitizeModelResponse(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, allowResponse)
	p := pluginWithStub(stub)

	in := execInput(policy.StagePreResponse, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), respCtx(openAIResponse(), false))
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if stub.count() != 1 {
		t.Fatalf("expected one sanitize call, got %d", stub.count())
	}
	if !strings.HasSuffix(stub.path(), ":sanitizeModelResponse") {
		t.Fatalf("path = %q, want suffix :sanitizeModelResponse", stub.path())
	}
}

func TestExecutePreRequestGuardPassThroughs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  *infracontext.RequestContext
	}{
		{"nil request", nil},
		{"empty body", reqCtx(nil)},
		{"empty provider", &infracontext.RequestContext{Provider: "", SourceFormat: "openai", Body: openAIRequest()}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stub := newModelArmorStub(t, http.StatusOK, allowResponse)
			p := pluginWithStub(stub)
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), tt.req, nil)
			res, err := p.Execute(context.Background(), in)
			assertPassThrough(t, res, err)
			if stub.count() != 0 {
				t.Fatalf("expected no sanitize call, got %d", stub.count())
			}
		})
	}
}

func TestExecutePreResponseStreamingPassThrough(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, raiBlockResponse)
	p := pluginWithStub(stub)

	in := execInput(policy.StagePreResponse, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), respCtx(openAIResponse(), true))
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if stub.count() != 0 {
		t.Fatalf("expected no sanitize call on streaming response, got %d", stub.count())
	}
}

func TestExecuteBlockEnforceReturns403(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, raiBlockResponse)
	p := pluginWithStub(stub)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on block, got %+v", res)
	}
	pe, ok := appplugins.AsPluginError(err)
	if !ok {
		t.Fatalf("expected *PluginError, got %v", err)
	}
	if pe.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", pe.StatusCode, http.StatusForbidden)
	}
	if pe.Type != typeModelArmorBlocked {
		t.Fatalf("type = %q, want %q", pe.Type, typeModelArmorBlocked)
	}
	var decoded struct {
		Error struct {
			Type   string `json:"type"`
			Filter string `json:"filter"`
		} `json:"error"`
	}
	if err := json.Unmarshal(pe.Body, &decoded); err != nil {
		t.Fatalf("decode block body: %v", err)
	}
	if decoded.Error.Filter != filterRAI {
		t.Fatalf("filter = %q, want %q", decoded.Error.Filter, filterRAI)
	}
}

func TestExecuteBlockObserveReports(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, raiBlockResponse)
	p := pluginWithStub(stub)

	in := execInput(policy.StagePreRequest, policy.ModeObserve, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if stub.count() != 1 {
		t.Fatalf("expected one sanitize call, got %d", stub.count())
	}
}

func TestExecuteBlockOnExcludesFilterFromBlocking(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, raiBlockResponse)
	p := pluginWithStub(stub)

	settings := modelArmorSettings()
	settings["block_on"] = []string{filterCSAM}
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings, reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
}

func TestExecuteClientErrorEnforceFailsClosed(t *testing.T) {
	t.Parallel()
	p := pluginWithClientError(errors.New("boom"))

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on fail-closed, got %+v", res)
	}
	if err == nil {
		t.Fatal("expected error on client failure in enforce mode")
		return
	}
	if _, ok := appplugins.AsPluginError(err); ok {
		t.Fatalf("expected non-PluginError on transport failure, got %v", err)
	}
}

func TestExecuteClientErrorObservePassesThrough(t *testing.T) {
	t.Parallel()
	p := pluginWithClientError(errors.New("boom"))

	in := execInput(policy.StagePreRequest, policy.ModeObserve, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
}

func TestExecuteInvocationFailureEnforceFailsClosed(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, invocationFailureResponse)
	p := pluginWithStub(stub)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on fail-closed, got %+v", res)
	}
	if err == nil {
		t.Fatal("expected error on invocationResult FAILURE in enforce mode")
	}
}

func TestExecuteInvocationFailureObservePassesThrough(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, invocationFailureResponse)
	p := pluginWithStub(stub)

	in := execInput(policy.StagePreRequest, policy.ModeObserve, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
}

func TestExecuteAnonymizeEnforcePreRequestRewritesBody(t *testing.T) {
	t.Parallel()
	const masked = "hello {EMAIL}"
	stub := newModelArmorStub(t, http.StatusOK, sdpAnonymizeResponse(masked))
	p := pluginWithStub(stub)

	settings := modelArmorSettings()
	settings["sdp_action"] = sdpActionAnonymize
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings, reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream {
		t.Fatalf("expected rewritten request result, got %+v", res)
	}
	if len(res.RequestBody) == 0 || res.Body != nil {
		t.Fatalf("expected RequestBody set and Body nil, got %+v", res)
	}
	creq, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
	if err != nil {
		t.Fatalf("decode rewritten body: %v", err)
	}
	last, idx := lastUserText(creq)
	if idx < 0 || last != masked {
		t.Fatalf("last user content = %q (idx %d), want %q", last, idx, masked)
	}
}

func TestExecuteAnonymizeEnforcePreResponseRewritesBody(t *testing.T) {
	t.Parallel()
	const masked = "the {SSN}"
	stub := newModelArmorStub(t, http.StatusOK, sdpAnonymizeResponse(masked))
	p := pluginWithStub(stub)

	settings := modelArmorSettings()
	settings["sdp_action"] = sdpActionAnonymize
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, settings, reqCtx(openAIRequest()), respCtx(openAIResponse(), false))
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || !res.StopUpstream {
		t.Fatalf("expected rewritten response with StopUpstream, got %+v", res)
	}
	if len(res.Body) == 0 || res.RequestBody != nil {
		t.Fatalf("expected Body set and RequestBody nil, got %+v", res)
	}
	cresp, err := adapter.NewRegistry().DecodeResponseFor(res.Body, adapter.FormatOpenAI)
	if err != nil {
		t.Fatalf("decode rewritten body: %v", err)
	}
	if cresp.Content != masked {
		t.Fatalf("response content = %q, want %q", cresp.Content, masked)
	}
}

func TestExecuteAnonymizeObserveDoesNotMutate(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, sdpAnonymizeResponse("hello {EMAIL}"))
	p := pluginWithStub(stub)

	settings := modelArmorSettings()
	settings["sdp_action"] = sdpActionAnonymize
	in := execInput(policy.StagePreRequest, policy.ModeObserve, settings, reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if stub.count() != 1 {
		t.Fatalf("expected one sanitize call, got %d", stub.count())
	}
}

func TestAnonymizeEnforceDegradedReasons(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, allowResponse))
	f := &finding{filter: filterSDP, infoTypes: []string{"EMAIL_ADDRESS"}}
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), nil)

	sdpResultWithText := func(text string) *SanitizationResult {
		return &SanitizationResult{FilterResults: FilterResults{SDP: &SDPFilterResult{SdpFilterResult: &SDPResult{
			DeidentifyResult: &SDPDeidentifyResult{MatchState: matchStateMatchFound, Data: &SDPData{Text: text}},
		}}}}
	}

	tests := []struct {
		name   string
		result *SanitizationResult
		span   rewriteSpan
		reason string
	}{
		{
			name:   "no output",
			result: &SanitizationResult{},
			span:   rewriteSpan{format: adapter.FormatOpenAI, rewrite: func(string) ([]byte, bool) { return []byte("x"), true }},
			reason: reasonAnonymizeNoOutput,
		},
		{
			name:   "unsupported format",
			result: sdpResultWithText("masked"),
			span:   rewriteSpan{format: unsupportedFormat, rewrite: func(string) ([]byte, bool) { return []byte("x"), true }},
			reason: reasonAnonymizeUnsupportedFormat,
		},
		{
			name:   "encode failed",
			result: sdpResultWithText("masked"),
			span:   rewriteSpan{format: adapter.FormatOpenAI, rewrite: func(string) ([]byte, bool) { return nil, false }},
			reason: reasonAnonymizeEncodeFailed,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := &Data{}
			res, err := p.anonymizeEnforce(in, data, tt.result, tt.span, f)
			if res != nil {
				t.Fatalf("expected nil result, got %+v", res)
			}
			if _, ok := appplugins.AsPluginError(err); !ok {
				t.Fatalf("expected *PluginError, got %v", err)
			}
			if !data.Degraded || data.DegradedReason != tt.reason {
				t.Fatalf("degraded = %t reason = %q, want true %q", data.Degraded, data.DegradedReason, tt.reason)
			}
			if data.Decision != decisionBlocked {
				t.Fatalf("decision = %q, want %q", data.Decision, decisionBlocked)
			}
		})
	}
}

func TestAnonymizeEnforceSuccessSetsDecision(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, allowResponse))
	f := &finding{filter: filterSDP}
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	data := &Data{}
	span := rewriteSpan{format: adapter.FormatOpenAI, rewrite: func(masked string) ([]byte, bool) {
		return []byte(masked), true
	}}
	result := &SanitizationResult{FilterResults: FilterResults{SDP: &SDPFilterResult{SdpFilterResult: &SDPResult{
		DeidentifyResult: &SDPDeidentifyResult{MatchState: matchStateMatchFound, Data: &SDPData{Text: "masked-body"}},
	}}}}

	res, err := p.anonymizeEnforce(in, data, result, span, f)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res == nil || res.RequestBody == nil || string(res.RequestBody) != "masked-body" {
		t.Fatalf("expected masked request body, got %+v", res)
	}
	if data.Degraded {
		t.Fatal("expected not degraded on success")
	}
	if data.Decision != decisionAnonymized {
		t.Fatalf("decision = %q, want %q", data.Decision, decisionAnonymized)
	}
}

func TestExecuteUnknownStagePassThrough(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, raiBlockResponse)
	p := pluginWithStub(stub)

	in := execInput(policy.StagePostResponse, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), respCtx(openAIResponse(), false))
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if stub.count() != 0 {
		t.Fatalf("expected no sanitize call on unsupported stage, got %d", stub.count())
	}
}

func TestPluginContract(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", 0, nil)
	if p.Name() != PluginName {
		t.Fatalf("Name = %q, want %q", p.Name(), PluginName)
	}
	if !p.MutatesRequestBody() {
		t.Fatal("MutatesRequestBody must be true")
	}
	if !p.MutatesResponseBody() {
		t.Fatal("MutatesResponseBody must be true")
	}
	if p.MutatesMetadata() {
		t.Fatal("MutatesMetadata must be false")
	}
	mandatory := p.MandatoryStages()
	if len(mandatory) != 1 || mandatory[0] != policy.StagePreRequest {
		t.Fatalf("MandatoryStages = %v, want [pre_request]", mandatory)
	}
	stages := p.SupportedStages()
	if len(stages) != 2 || stages[0] != policy.StagePreRequest || stages[1] != policy.StagePreResponse {
		t.Fatalf("SupportedStages = %v", stages)
	}
	modes := p.SupportedModes()
	if len(modes) != 2 || modes[0] != policy.ModeEnforce || modes[1] != policy.ModeObserve {
		t.Fatalf("SupportedModes = %v", modes)
	}
}

func TestValidateConfigRejectsMissingProject(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", 0, nil)
	set := modelArmorSettings()
	delete(set, "project")
	if err := p.ValidateConfig(set); err == nil {
		t.Fatal("expected validation error for missing project")
	}
}
