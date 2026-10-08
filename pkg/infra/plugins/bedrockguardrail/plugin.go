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
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

const PluginName = "bedrock_guardrail"

const (
	decisionBlocked    = "blocked"
	decisionAnonymized = "anonymized"
	decisionReported   = "reported"
	decisionAllowed    = "allowed"
)

const (
	reasonAnonymizeNoOutput          = "anonymize_no_output"
	reasonAnonymizeUnsupportedFormat = "anonymize_unsupported_format"
	reasonAnonymizeEncodeFailed      = "anonymize_encode_failed"
)

const roleUser = "user"

var _ appplugins.Plugin = (*Plugin)(nil)

type rewriteSpan struct {
	format     adapter.Format
	isResponse bool
	rewrite    func(masked string) ([]byte, bool)
}

func (s rewriteSpan) result(body []byte) *appplugins.Result {
	if s.isResponse {
		return &appplugins.Result{StatusCode: http.StatusOK, Body: body, StopUpstream: true}
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}
}

type Plugin struct {
	registry   *adapter.Registry
	guardrails *cachedGuardrailClient
	logger     *slog.Logger
}

func New(registry *adapter.Registry, logger *slog.Logger) *Plugin {
	return &Plugin{
		registry:   registry,
		guardrails: newCachedGuardrailClient(),
		logger:     logger,
	}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MutatesRequestBody() bool { return true }

func (p *Plugin) MutatesResponseBody() bool { return true }

func (p *Plugin) MutatesMetadata() bool { return false }

// BedrockNative declares what the plugin does on a native Amazon Bedrock Runtime
// call (see appplugins.BedrockNativeAware).
func (p *Plugin) BedrockNative() appplugins.BedrockNativeBehavior {
	return appplugins.BedrockNativeMasks
}

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

var _ appplugins.SettingsWriteValidator = (*Plugin)(nil)

// ValidateSettingsWrite rejects a new streaming.final_pass: false, which the
// block loop cannot honour (pluginutil.ValidateFinalPassWrite).
func (p *Plugin) ValidateSettingsWrite(settings, previous map[string]any) error {
	return pluginutil.ValidateFinalPassWrite(PluginName, settings, previous)
}

// CredentialPaths declares the settings paths that hold secrets, so the policy
// API masks them on read: the AWS credentials nested under "credentials".
func (p *Plugin) CredentialPaths() []string {
	return []string{
		"credentials.access_key_id",
		"credentials.secret_access_key",
		"credentials.session_token",
	}
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureConfigInvalid, "", err)
	}
	switch in.Stage {
	case policy.StagePreRequest:
		return p.executePreRequest(ctx, in, cfg)
	case policy.StagePreResponse:
		return p.executePreResponse(ctx, in, cfg)
	default:
		return passThrough(), nil
	}
}

func (p *Plugin) executePreRequest(ctx context.Context, in appplugins.ExecInput, cfg Settings) (*appplugins.Result, error) {
	if in.Request == nil || len(in.Request.Body) == 0 || in.Request.Provider == "" || p.registry == nil {
		return passThrough(), nil
	}
	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureDecodeFailed, "", err)
	}
	creq, err := p.registry.DecodeRequestFor(in.Request.Body, format)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureDecodeFailed, "", err)
	}
	if creq == nil {
		return passThrough(), nil
	}
	text, idx := lastUserText(creq)
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}
	span := rewriteSpan{
		format: format,
		rewrite: func(masked string) ([]byte, bool) {
			return rewriteRequest(p.registry, format, in.Request.Body, creq, idx, masked)
		},
	}
	return p.runGuardrail(ctx, in, cfg, text, types.GuardrailContentSourceInput, span)
}

func (p *Plugin) executePreResponse(ctx context.Context, in appplugins.ExecInput, cfg Settings) (*appplugins.Result, error) {
	if in.Request == nil || in.Response == nil {
		return passThrough(), nil
	}
	// A streamed response is inspected block by block by the stream guard when
	// streaming is enabled for this policy. When it is not, the response goes
	// out uninspected and the trace says so, rather than omitting the policy.
	if in.Response.Streaming {
		if !cfg.Streaming.IsEnabled() {
			pluginutil.RecordStreamingDisabled(in.Event, string(in.Stage))
		}
		return passThrough(), nil
	}
	if p.registry == nil || in.Request.Provider == "" || len(in.Response.Body) == 0 {
		return passThrough(), nil
	}
	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureDecodeFailed, "", err)
	}
	cresp, err := p.registry.DecodeResponseFor(in.Response.Body, format)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureDecodeFailed, "", err)
	}
	if cresp == nil {
		return passThrough(), nil
	}
	text := responseText(cresp)
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}
	span := rewriteSpan{
		format:     format,
		isResponse: true,
		rewrite: func(masked string) ([]byte, bool) {
			return rewriteResponse(p.registry, format, cresp, masked)
		},
	}
	return p.runGuardrail(ctx, in, cfg, text, types.GuardrailContentSourceOutput, span)
}

func (p *Plugin) runGuardrail(ctx context.Context, in appplugins.ExecInput, cfg Settings, text string, source types.GuardrailContentSource, span rewriteSpan) (*appplugins.Result, error) {
	start := time.Now()
	out, err := p.guardrails.ApplyGuardrail(ctx, credentialsFromConfig(cfg.Credentials), buildApplyInput(cfg, text, source))
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return p.externalFailure(ctx, in, cfg, latency, appplugins.FailureTransport, "",
			fmt.Errorf("apply guardrail: %w", err))
	}

	res := inspect(out, cfg.PIIAction)

	// The guardrail intervened, but none of the policy types this plugin reads
	// (topic, content, word, sensitive-information, contextual-grounding)
	// produced a finding to explain it — an intervention type AWS added that
	// this plugin does not yet parse. Reading that as a clean pass would be a
	// guardrail that quietly stopped guarding.
	if res.intervened && res.block == nil && res.anonymize == nil {
		return p.externalFailure(ctx, in, cfg, latency, appplugins.FailureVerdictIncomplete, unparsedPolicies(out.Assessments),
			fmt.Errorf("guardrail intervened with no block or anonymize finding"))
	}

	data := newData(in, cfg, latency)

	if res.block != nil {
		applyFinding(data, res.block)
		recordScore(in.Event, data)
		if appplugins.Blocks(in.Mode) {
			data.Decision = decisionBlocked
			setExtras(in.Event, data)
			appplugins.SetDecisionFromOutcome(in.Event, decisionBlocked)
			return nil, blockError(cfg.Message, *res.block)
		}
		data.Decision = decisionReported
		setExtras(in.Event, data)
		appplugins.SetDecisionFromOutcome(in.Event, decisionReported)
		return passThrough(), nil
	}

	if res.anonymize != nil {
		applyFinding(data, res.anonymize)
		recordScore(in.Event, data)
		if appplugins.Blocks(in.Mode) {
			return p.anonymizeEnforce(in, data, cfg.Message, out, span, res.anonymize)
		}
		data.Decision = decisionReported
		setExtras(in.Event, data)
		appplugins.SetDecisionFromOutcome(in.Event, decisionReported)
		return passThrough(), nil
	}

	data.Decision = decisionAllowed
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, decisionAllowed)
	return passThrough(), nil
}

func (p *Plugin) anonymizeEnforce(in appplugins.ExecInput, data *Data, message string, out *bedrockruntime.ApplyGuardrailOutput, span rewriteSpan, f *finding) (*appplugins.Result, error) {
	masked, ok := maskedText(out)
	if !ok {
		return p.anonymizeDegraded(in, data, message, reasonAnonymizeNoOutput, f)
	}
	if !supportsReencode(p.registry, span.format) {
		return p.anonymizeDegraded(in, data, message, reasonAnonymizeUnsupportedFormat, f)
	}
	body, ok := span.rewrite(masked)
	if !ok {
		return p.anonymizeDegraded(in, data, message, reasonAnonymizeEncodeFailed, f)
	}
	data.Decision = decisionAnonymized
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, decisionAnonymized)
	return span.result(body), nil
}

// anonymizeDegraded blocks by design (RUN-1792): the provider confirmed sensitive data and gave no way to mask it, so this is the one deliberate exception to fail-open.
func (p *Plugin) anonymizeDegraded(in appplugins.ExecInput, data *Data, message string, reason string, f *finding) (*appplugins.Result, error) {
	data.Degraded = true
	data.DegradedReason = reason
	data.Decision = decisionBlocked
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, decisionBlocked)
	return nil, blockError(message, *f)
}

// externalFailure turns a failed guardrail call into a plugin outcome via the
// shared appplugins.HandleExternalFailure: on the buffered leg it always fails
// open (pass through, decision failed_open), in every mode and for every
// reason (RUN-1792). It builds this plugin's own Data so
// failure_reason/failure_detail travel in the same shape as every other
// external guardrail.
func (p *Plugin) externalFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	latencyMS int64,
	reason appplugins.FailureReason,
	detail string,
	err error,
) (*appplugins.Result, error) {
	outcome := appplugins.HandleExternalFailure(appplugins.ExternalFailure{
		Ctx:    ctx,
		Plugin: PluginName,
		Stage:  in.Stage,
		Mode:   in.Mode,
		Reason: reason,
		Detail: detail,
		Err:    err,
		Logger: p.logger,
		Event:  in.Event,
	})
	data := newData(in, cfg, latencyMS)
	data.Decision = outcome.Decision
	data.FailureReason = string(reason)
	data.FailureDetail = detail
	setExtras(in.Event, data)
	return outcome.Result, outcome.Err
}

func newData(in appplugins.ExecInput, cfg Settings, latency int64) *Data {
	return &Data{
		GuardrailID: cfg.GuardrailID,
		Version:     cfg.Version,
		Region:      cfg.Credentials.AWSRegion,
		Stage:       string(in.Stage),
		Mode:        string(in.Mode),
		LatencyMS:   latency,
	}
}

func applyFinding(data *Data, f *finding) {
	data.Policy = f.policy
	data.MatchType = f.matchType
	data.Action = f.action
	data.Name = f.name
}

func lastUserText(creq *adapter.CanonicalRequest) (string, int) {
	if creq == nil {
		return "", -1
	}
	for i := len(creq.Messages) - 1; i >= 0; i-- {
		msg := creq.Messages[i]
		if msg.Role == roleUser && strings.TrimSpace(msg.Content) != "" {
			return msg.Content, i
		}
	}
	return "", -1
}

func responseText(cresp *adapter.CanonicalResponse) string {
	if cresp == nil {
		return ""
	}
	return cresp.Content
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
