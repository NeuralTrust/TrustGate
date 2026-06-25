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

func TestExecuteAnonymizeFindingReportsInPhase4a(t *testing.T) {
	t.Parallel()
	client := &recordingClient{output: piiAnonymizedOutput()}
	p := pluginWith(client)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionAnonymize), reqCtx(openAIRequest()), nil)
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if client.count() != 1 {
		t.Fatalf("expected one guardrail call, got %d", client.count())
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
