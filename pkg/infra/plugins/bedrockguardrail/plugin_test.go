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
	"errors"
	"net/http"
	"sync"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

type recordingClient struct {
	mu        sync.Mutex
	calls     int
	lastInput *bedrockruntime.ApplyGuardrailInput
	output    *bedrockruntime.ApplyGuardrailOutput
	err       error
}

func (c *recordingClient) ApplyGuardrail(
	_ context.Context,
	in *bedrockruntime.ApplyGuardrailInput,
	_ ...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.lastInput = in
	return c.output, c.err
}

func (c *recordingClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *recordingClient) source() types.GuardrailContentSource {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastInput == nil {
		return ""
	}
	return c.lastInput.Source
}

func pluginWith(client guardrailClient) *Plugin {
	return &Plugin{
		registry: adapter.NewRegistry(),
		guardrails: &cachedGuardrailClient{
			cache: &clientCache{
				build: func(context.Context, awsCredentials) (guardrailClient, error) {
					return client, nil
				},
			},
		},
	}
}

func bedrockSettings(piiAction string) map[string]any {
	return map[string]any{
		"guardrail_id": "gr-123",
		"version":      "DRAFT",
		"pii_action":   piiAction,
		"credentials": map[string]any{
			"aws_region":        "us-east-1",
			"access_key_id":     "AKIAEXAMPLE",
			"secret_access_key": "secret",
		},
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

func allowOutput() *bedrockruntime.ApplyGuardrailOutput {
	return &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}
}

func topicBlockedOutput() *bedrockruntime.ApplyGuardrailOutput {
	return intervened(types.GuardrailAssessment{
		TopicPolicy: &types.GuardrailTopicPolicyAssessment{
			Topics: []types.GuardrailTopic{{
				Action: types.GuardrailTopicPolicyActionBlocked,
				Name:   aws.String("Investment Advice"),
				Type:   types.GuardrailTopicTypeDeny,
			}},
		},
	})
}

func piiAnonymizedOutput() *bedrockruntime.ApplyGuardrailOutput {
	return intervened(types.GuardrailAssessment{
		SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
			PiiEntities: []types.GuardrailPiiEntityFilter{{
				Action: types.GuardrailSensitiveInformationPolicyActionAnonymized,
				Match:  aws.String("john@example.com"),
				Type:   types.GuardrailPiiEntityTypeEmail,
			}},
		},
	})
}

func piiAnonymizedOutputWithText(masked string) *bedrockruntime.ApplyGuardrailOutput {
	out := piiAnonymizedOutput()
	out.Outputs = []types.GuardrailOutputContent{{Text: aws.String(masked)}}
	return out
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

func TestExecutePreRequestUsesInputSource(t *testing.T) {
	t.Parallel()
	client := &recordingClient{output: allowOutput()}
	p := pluginWith(client)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if client.count() != 1 {
		t.Fatalf("expected one guardrail call, got %d", client.count())
	}
	if client.source() != types.GuardrailContentSourceInput {
		t.Fatalf("source = %q, want INPUT", client.source())
	}
}

func TestExecutePreResponseUsesOutputSource(t *testing.T) {
	t.Parallel()
	client := &recordingClient{output: allowOutput()}
	p := pluginWith(client)

	in := execInput(policy.StagePreResponse, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), respCtx(openAIResponse(), false))
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if client.count() != 1 {
		t.Fatalf("expected one guardrail call, got %d", client.count())
	}
	if client.source() != types.GuardrailContentSourceOutput {
		t.Fatalf("source = %q, want OUTPUT", client.source())
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := &recordingClient{output: allowOutput()}
			p := pluginWith(client)
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionBlock), tt.req, nil)
			res, err := p.Execute(context.Background(), in)
			assertPassThrough(t, res, err)
			if client.count() != 0 {
				t.Fatalf("expected no guardrail call, got %d", client.count())
			}
		})
	}
}

func TestExecutePreResponseStreamingPassThrough(t *testing.T) {
	t.Parallel()
	client := &recordingClient{output: topicBlockedOutput()}
	p := pluginWith(client)

	in := execInput(policy.StagePreResponse, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), respCtx(openAIResponse(), true))
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if client.count() != 0 {
		t.Fatalf("expected no guardrail call on streaming response, got %d", client.count())
	}
}

func TestExecuteBlockEnforceReturns403(t *testing.T) {
	t.Parallel()
	client := &recordingClient{output: topicBlockedOutput()}
	p := pluginWith(client)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), nil)
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
	if pe.Type != typeGuardrailBlocked {
		t.Fatalf("type = %q, want %q", pe.Type, typeGuardrailBlocked)
	}
	var decoded struct {
		Error struct {
			Type   string `json:"type"`
			Policy string `json:"policy"`
			Name   string `json:"name"`
		} `json:"error"`
	}
	if err := json.Unmarshal(pe.Body, &decoded); err != nil {
		t.Fatalf("decode block body: %v", err)
	}
	if decoded.Error.Policy != policyTopic {
		t.Fatalf("policy = %q, want %q", decoded.Error.Policy, policyTopic)
	}
	if decoded.Error.Name != "Investment Advice" {
		t.Fatalf("name = %q, want %q", decoded.Error.Name, "Investment Advice")
	}
}

func TestExecuteBlockObserveReports(t *testing.T) {
	t.Parallel()
	client := &recordingClient{output: topicBlockedOutput()}
	p := pluginWith(client)

	in := execInput(policy.StagePreRequest, policy.ModeObserve, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if client.count() != 1 {
		t.Fatalf("expected one guardrail call, got %d", client.count())
	}
}

func TestExecuteClientErrorEnforceFailsClosed(t *testing.T) {
	t.Parallel()
	client := &recordingClient{err: errors.New("boom")}
	p := pluginWith(client)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on fail-closed, got %+v", res)
	}
	if err == nil {
		t.Fatal("expected error on client failure in enforce mode")
	}
	if _, ok := appplugins.AsPluginError(err); ok {
		t.Fatalf("expected non-PluginError on transport failure, got %v", err)
	}
}

func TestExecuteClientErrorObservePassesThrough(t *testing.T) {
	t.Parallel()
	client := &recordingClient{err: errors.New("boom")}
	p := pluginWith(client)

	in := execInput(policy.StagePreRequest, policy.ModeObserve, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
}

func TestExecuteAnonymizeEnforcePreRequestRewritesBody(t *testing.T) {
	t.Parallel()
	const masked = "hello {EMAIL}"
	client := &recordingClient{output: piiAnonymizedOutputWithText(masked)}
	p := pluginWith(client)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionAnonymize), reqCtx(openAIRequest()), nil)
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
	client := &recordingClient{output: piiAnonymizedOutputWithText(masked)}
	p := pluginWith(client)

	in := execInput(policy.StagePreResponse, policy.ModeEnforce, bedrockSettings(piiActionAnonymize), reqCtx(openAIRequest()), respCtx(openAIResponse(), false))
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
	client := &recordingClient{output: piiAnonymizedOutputWithText("hello {EMAIL}")}
	p := pluginWith(client)

	in := execInput(policy.StagePreRequest, policy.ModeObserve, bedrockSettings(piiActionAnonymize), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if client.count() != 1 {
		t.Fatalf("expected one guardrail call, got %d", client.count())
	}
}

func TestExecuteAnonymizeEnforceNoOutputFailsClosed(t *testing.T) {
	t.Parallel()
	client := &recordingClient{output: piiAnonymizedOutput()}
	p := pluginWith(client)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionAnonymize), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on degraded fail-closed, got %+v", res)
	}
	pe, ok := appplugins.AsPluginError(err)
	if !ok {
		t.Fatalf("expected *PluginError, got %v", err)
	}
	if pe.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", pe.StatusCode, http.StatusForbidden)
	}
	if pe.Type != typeGuardrailBlocked {
		t.Fatalf("type = %q, want %q", pe.Type, typeGuardrailBlocked)
	}
}

func TestAnonymizeEnforceDegradedReasons(t *testing.T) {
	t.Parallel()
	p := pluginWith(&recordingClient{})
	f := &finding{policy: policySensitiveInformation, name: "EMAIL"}
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionAnonymize), reqCtx(openAIRequest()), nil)

	tests := []struct {
		name   string
		out    *bedrockruntime.ApplyGuardrailOutput
		span   rewriteSpan
		reason string
	}{
		{
			name:   "no output",
			out:    &bedrockruntime.ApplyGuardrailOutput{},
			span:   rewriteSpan{format: adapter.FormatOpenAI, rewrite: func(string) ([]byte, bool) { return []byte("x"), true }},
			reason: reasonAnonymizeNoOutput,
		},
		{
			name:   "unsupported format",
			out:    piiAnonymizedOutputWithText("masked"),
			span:   rewriteSpan{format: unsupportedFormat, rewrite: func(string) ([]byte, bool) { return []byte("x"), true }},
			reason: reasonAnonymizeUnsupportedFormat,
		},
		{
			name:   "encode failed",
			out:    piiAnonymizedOutputWithText("masked"),
			span:   rewriteSpan{format: adapter.FormatOpenAI, rewrite: func(string) ([]byte, bool) { return nil, false }},
			reason: reasonAnonymizeEncodeFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := &Data{}
			res, err := p.anonymizeEnforce(in, data, tt.out, tt.span, f)
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
	p := pluginWith(&recordingClient{})
	f := &finding{policy: policySensitiveInformation, name: "EMAIL"}
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionAnonymize), reqCtx(openAIRequest()), nil)
	data := &Data{}
	span := rewriteSpan{format: adapter.FormatOpenAI, rewrite: func(masked string) ([]byte, bool) {
		return []byte(masked), true
	}}

	res, err := p.anonymizeEnforce(in, data, piiAnonymizedOutputWithText("masked-body"), span, f)
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
	client := &recordingClient{output: topicBlockedOutput()}
	p := pluginWith(client)

	in := execInput(policy.StagePostResponse, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), respCtx(openAIResponse(), false))
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if client.count() != 0 {
		t.Fatalf("expected no guardrail call on unsupported stage, got %d", client.count())
	}
}

func TestPluginContract(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
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
	if len(p.MandatoryStages()) != 0 {
		t.Fatalf("MandatoryStages = %v, want empty", p.MandatoryStages())
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

func TestValidateConfigRejectsMissingGuardrailID(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := bedrockSettings(piiActionBlock)
	delete(set, "guardrail_id")
	if err := p.ValidateConfig(set); err == nil {
		t.Fatal("expected validation error for missing guardrail_id")
	}
}
