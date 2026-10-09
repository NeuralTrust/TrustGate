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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"sync"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

func eventFor(t *testing.T) (*metrics.EventContext, *trace.Span) {
	t.Helper()
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)
	return metrics.NewEventContext(span), span
}

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

func TestExecuteClientErrorEnforceFailsOpen(t *testing.T) {
	t.Parallel()
	client := &recordingClient{err: errors.New("boom")}
	p := pluginWith(client)

	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), nil)
	in.Event = event
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	if !ok || extras.Decision != "failed_open" || extras.FailureReason != "transport" {
		t.Fatalf("extras = %+v, ok=%v, want transport/failed_open", extras, ok)
	}
}

// An intervention none of the read policy families can explain is not a clean
// pass: AWS intervened on this content, so a mode that blocks refuses it
// (failed_closed) and observe only records it.
func TestExecuteUnparsedInterventionByMode(t *testing.T) {
	t.Parallel()
	// A policy type AWS added that this plugin does not yet parse.
	unparsed := intervened(types.GuardrailAssessment{})
	named := intervened(types.GuardrailAssessment{
		AutomatedReasoningPolicy: &types.GuardrailAutomatedReasoningPolicyAssessment{},
	})
	for _, tc := range []struct {
		name     string
		output   *bedrockruntime.ApplyGuardrailOutput
		mode     policy.Mode
		decision string
		refused  bool
		policies string
	}{
		{"enforce", unparsed, policy.ModeEnforce, "failed_closed", true, ""},
		{"enforce names the policy", named, policy.ModeEnforce, "failed_closed", true, "automated_reasoning_policy"},
		{"throttle", unparsed, policy.ModeThrottle, "failed_closed", true, ""},
		{"observe", unparsed, policy.ModeObserve, "failed_open", false, ""},
		{"observe names the policy", named, policy.ModeObserve, "failed_open", false, "automated_reasoning_policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := pluginWith(&recordingClient{output: tc.output})
			event, span := eventFor(t)
			in := execInput(policy.StagePreRequest, tc.mode, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), nil)
			in.Event = event
			res, err := p.Execute(context.Background(), in)
			if tc.refused {
				pe, ok := appplugins.AsPluginError(err)
				if !ok || pe.StatusCode != http.StatusForbidden || pe.Type != appplugins.TypeGuardrailInputUninspectable {
					t.Fatalf("want a 403 guardrail_input_uninspectable, got res=%+v err=%v", res, err)
				}
			} else {
				assertPassThrough(t, res, err)
			}
			extras, ok := span.PluginAttrsCopy().Extras.(*Data)
			if !ok || extras.Decision != tc.decision || extras.FailureReason != "verdict_incomplete" ||
				extras.FailureDetail != "intervention_unparsed" || extras.FailurePolicies != tc.policies || extras.FailureClass != "input" {
				t.Fatalf("extras = %+v, ok=%v, want %s verdict_incomplete/intervention_unparsed policies=%q class input", extras, ok, tc.decision, tc.policies)
			}
		})
	}
}

// What ApplyGuardrail answers is classified by the AWS error type and status, in
// the shapes the SDK parses off the wire: a client error about the call is the
// content's and is refused in a mode that blocks; credentials, throttling,
// timeouts and 5xx stay availability and fail open.
func TestExecuteProviderErrorByClass(t *testing.T) {
	t.Parallel()
	for _, tc := range awsApplyGuardrailErrors {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(tc.name+" "+string(mode), func(t *testing.T) {
				t.Parallel()
				awsErr := applyGuardrailAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("X-Amzn-Errortype", tc.errType+":http://internal.amazon.com/coral/com.amazon.bedrock/")
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(`{"message":"` + tc.message + `"}`))
				})
				p := pluginWith(&recordingClient{err: awsErr})
				event, span := eventFor(t)
				in := execInput(policy.StagePreRequest, mode, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), nil)
				in.Event = event
				res, err := p.Execute(context.Background(), in)

				input := tc.reason == appplugins.FailureInputTooLarge
				wantDecision, wantClass, refused := "failed_open", "availability", false
				if input {
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
				extras, ok := span.PluginAttrsCopy().Extras.(*Data)
				if !ok || extras.Decision != wantDecision || extras.FailureClass != wantClass || extras.FailureReason != string(tc.reason) {
					t.Fatalf("extras = %+v, ok=%v, want %s/%s/%s", extras, ok, wantDecision, wantClass, tc.reason)
				}
			})
		}
	}
}

func TestExecuteConfigInvalidEnforceFailsOpen(t *testing.T) {
	t.Parallel()
	p := pluginWith(&recordingClient{})

	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, map[string]any{}, reqCtx(openAIRequest()), nil)
	in.Event = event
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	if !ok || extras.Decision != "failed_open" || extras.FailureReason != "config_invalid" {
		t.Fatalf("extras = %+v, ok=%v, want config_invalid/failed_open", extras, ok)
	}
}

func TestExecuteConfigInvalidObserveFailsOpen(t *testing.T) {
	t.Parallel()
	p := pluginWith(&recordingClient{})

	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeObserve, map[string]any{}, reqCtx(openAIRequest()), nil)
	in.Event = event
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	if !ok || extras.Decision != "failed_open" || extras.FailureReason != "config_invalid" {
		t.Fatalf("extras = %+v, ok=%v, want config_invalid/failed_open", extras, ok)
	}
}

// A body the adapters cannot read is the client's: in a mode that blocks the
// call is refused as uninspectable, and in observe it is only recorded.
func TestExecuteDecodeFailedIsAnInputFailure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode     policy.Mode
		decision string
		refused  bool
	}{
		{policy.ModeEnforce, "failed_closed", true},
		{policy.ModeObserve, "failed_open", false},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			client := &recordingClient{output: allowOutput()}
			p := pluginWith(client)
			req := reqCtx(openAIRequest())
			req.Provider = "not-a-real-provider"
			req.SourceFormat = ""
			event, span := eventFor(t)
			in := execInput(policy.StagePreRequest, tc.mode, bedrockSettings(piiActionBlock), req, nil)
			in.Event = event
			res, err := p.Execute(context.Background(), in)
			if tc.refused {
				pe, ok := appplugins.AsPluginError(err)
				if !ok || pe.StatusCode != http.StatusForbidden || pe.Type != appplugins.TypeGuardrailInputUninspectable {
					t.Fatalf("want a 403 guardrail_input_uninspectable, got res=%+v err=%v", res, err)
				}
			} else {
				assertPassThrough(t, res, err)
			}
			if client.count() != 0 {
				t.Fatalf("expected guardrail not called on decode failure, got %d calls", client.count())
			}
			extras, ok := span.PluginAttrsCopy().Extras.(*Data)
			if !ok || extras.Decision != tc.decision || extras.FailureReason != "decode_failed" || extras.FailureClass != "input" {
				t.Fatalf("extras = %+v, ok=%v, want decode_failed/%s/input", extras, ok, tc.decision)
			}
		})
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

// A mask that cannot be applied over a confirmed finding refuses the call with
// the finding's own block: forwarding the original would send the data the
// policy ruled out. It is recorded blocked and degraded, not failed_closed,
// because a finding exists.
func TestExecuteAnonymizeEnforceNoOutputBlocks(t *testing.T) {
	t.Parallel()
	for _, stage := range []policy.Stage{policy.StagePreRequest, policy.StagePreResponse} {
		t.Run(string(stage), func(t *testing.T) {
			t.Parallel()
			client := &recordingClient{output: piiAnonymizedOutput()}
			p := pluginWith(client)

			event, span := eventFor(t)
			in := execInput(stage, policy.ModeEnforce, bedrockSettings(piiActionAnonymize), reqCtx(openAIRequest()), respCtx(openAIResponse(), false))
			in.Event = event
			res, err := p.Execute(context.Background(), in)
			if res != nil {
				t.Fatalf("expected nil result on a blocked mask, got %+v", res)
			}
			pe, ok := appplugins.AsPluginError(err)
			if !ok || pe.StatusCode != http.StatusForbidden || pe.Type != typeGuardrailBlocked {
				t.Fatalf("want a 403 %s, got %v", typeGuardrailBlocked, err)
			}
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			if !ok {
				t.Fatalf("extras = %T, want *Data", span.PluginAttrsCopy().Extras)
			}
			if data.Decision != decisionBlocked || !data.Degraded || data.DegradedReason != reasonAnonymizeNoOutput ||
				data.FailureReason != "verdict_incomplete" || data.FailureDetail != reasonAnonymizeNoOutput || data.FailureClass != "input" {
				t.Fatalf("extras = %+v, want blocked + degraded %q, verdict_incomplete/%s, class input", data, reasonAnonymizeNoOutput, reasonAnonymizeNoOutput)
			}
		})
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
			res, err := p.anonymizeEnforce(context.Background(), in, data, "", tt.out, tt.span, f)
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

	res, err := p.anonymizeEnforce(context.Background(), in, data, "", piiAnonymizedOutputWithText("masked-body"), span, f)
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

func TestValidateConfigRejectsMissingGuardrailID(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := bedrockSettings(piiActionBlock)
	delete(set, "guardrail_id")
	if err := p.ValidateConfig(set); err == nil {
		t.Fatal("expected validation error for missing guardrail_id")
	}
}

func withRemovedKeys(set map[string]any) map[string]any {
	set["on_error"] = "fail_closed"
	set["on_timeout"] = "fail_closed"
	set["timeout"] = "1ms"
	set["on_mask_failure"] = "block"
	set["streaming"] = map[string]any{"enabled": true, "on_error": "fail_closed", "guard_timeout": "1ms"}
	return set
}

// on_error, streaming.on_error and streaming.guard_timeout are not guardrail settings: a
// policy stored with them keeps loading, fails open on a client error, and runs its
// stream leg fail open under the default guard timeout.
func TestStoredRemovedKeysAreIgnored(t *testing.T) {
	t.Parallel()
	p := pluginWith(&recordingClient{err: errors.New("boom")})

	if err := p.ValidateConfig(withRemovedKeys(bedrockSettings(piiActionBlock))); err != nil {
		t.Fatalf("a stored policy with removed keys must keep loading, got %v", err)
	}
	invalid := bedrockSettings(piiActionBlock)
	invalid["on_error"] = "retry"
	if err := p.ValidateConfig(invalid); err != nil {
		t.Fatalf("a stored invalid on_error must not reject a write, got %v", err)
	}

	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, withRemovedKeys(bedrockSettings(piiActionBlock)), reqCtx(openAIRequest()), nil)
	in.Event = event
	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	if !ok || extras.Decision != "failed_open" || extras.FailureReason != "transport" {
		t.Fatalf("extras = %+v, ok=%v, want transport/failed_open", extras, ok)
	}

	on, opts := p.StreamSettings(withRemovedKeys(bedrockSettings(piiActionBlock)))
	if !on || opts.OnError != "fail_open" {
		t.Fatalf("stream opt-in = %v, on_error = %q, want fail_open", on, opts.OnError)
	}
}

// on_mask_failure is not a setting: a mask that cannot be applied to a native Bedrock
// call always fails open. A policy stored with the key keeps loading, whatever
// its value, and the key changes nothing.
func TestOnMaskFailureIsIgnored(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	assert.Equal(t, appplugins.BedrockNativeMasks, appplugins.BedrockNativeOf(p))
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(p))
	for _, value := range []string{"pass", "block", "explode"} {
		set := bedrockSettings(piiActionBlock)
		set["on_mask_failure"] = value
		assert.NoError(t, p.ValidateConfig(set), value)
		assert.NoError(t, reg.Validate(p.Name(), set), value)
	}
}
