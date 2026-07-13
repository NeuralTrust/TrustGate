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
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

const PluginName = "bedrock_guardrail"

const (
	decisionBlocked      = "blocked"
	decisionAnonymized   = "anonymized"
	decisionReported     = "reported"
	decisionAllowed      = "allowed"
	decisionFailedClosed = "failed_closed"
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

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("bedrock_guardrail: %w", err)
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
		return passThrough(), nil
	}
	creq, err := p.registry.DecodeRequestFor(in.Request.Body, format)
	if err != nil || creq == nil {
		return passThrough(), nil
	}
	text, idx := lastUserText(creq)
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}
	span := rewriteSpan{
		format: format,
		rewrite: func(masked string) ([]byte, bool) {
			return rewriteRequest(p.registry, format, creq, idx, masked)
		},
	}
	return p.runGuardrail(ctx, in, cfg, text, types.GuardrailContentSourceInput, span)
}

func (p *Plugin) executePreResponse(ctx context.Context, in appplugins.ExecInput, cfg Settings) (*appplugins.Result, error) {
	if in.Request == nil || in.Response == nil || p.registry == nil {
		return passThrough(), nil
	}
	if in.Request.Provider == "" || len(in.Response.Body) == 0 {
		return passThrough(), nil
	}
	if in.Response.Streaming {
		return passThrough(), nil
	}
	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return passThrough(), nil
	}
	cresp, err := p.registry.DecodeResponseFor(in.Response.Body, format)
	if err != nil || cresp == nil {
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
		return p.failClosed(ctx, in, cfg, latency, err)
	}

	res := inspect(out, cfg.PIIAction)
	data := newData(in, cfg, latency)

	if res.block != nil {
		applyFinding(data, res.block)
		if appplugins.Blocks(in.Mode) {
			data.Decision = decisionBlocked
			setExtras(in.Event, data)
			appplugins.SetDecisionFromOutcome(in.Event, decisionBlocked)
			return nil, blockError(*res.block)
		}
		data.Decision = decisionReported
		setExtras(in.Event, data)
		appplugins.SetDecisionFromOutcome(in.Event, decisionReported)
		return passThrough(), nil
	}

	if res.anonymize != nil {
		applyFinding(data, res.anonymize)
		if appplugins.Blocks(in.Mode) {
			return p.anonymizeEnforce(in, data, out, span, res.anonymize)
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

func (p *Plugin) anonymizeEnforce(in appplugins.ExecInput, data *Data, out *bedrockruntime.ApplyGuardrailOutput, span rewriteSpan, f *finding) (*appplugins.Result, error) {
	masked, ok := maskedText(out)
	if !ok {
		return p.anonymizeDegraded(in, data, reasonAnonymizeNoOutput, f)
	}
	if !supportsReencode(p.registry, span.format) {
		return p.anonymizeDegraded(in, data, reasonAnonymizeUnsupportedFormat, f)
	}
	body, ok := span.rewrite(masked)
	if !ok {
		return p.anonymizeDegraded(in, data, reasonAnonymizeEncodeFailed, f)
	}
	data.Decision = decisionAnonymized
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, decisionAnonymized)
	return span.result(body), nil
}

func (p *Plugin) anonymizeDegraded(in appplugins.ExecInput, data *Data, reason string, f *finding) (*appplugins.Result, error) {
	data.Degraded = true
	data.DegradedReason = reason
	data.Decision = decisionBlocked
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, decisionBlocked)
	return nil, blockError(*f)
}

func (p *Plugin) failClosed(ctx context.Context, in appplugins.ExecInput, cfg Settings, latency int64, err error) (*appplugins.Result, error) {
	data := newData(in, cfg, latency)
	data.Decision = decisionFailedClosed
	if appplugins.Blocks(in.Mode) {
		p.debug(ctx, "bedrock guardrail call failed, failing closed",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
			slog.Any("error", err),
		)
		setExtras(in.Event, data)
		return nil, fmt.Errorf("bedrock_guardrail: apply guardrail: %w", err)
	}
	p.debug(ctx, "bedrock guardrail call failed, observe mode passing through",
		slog.String("plugin", PluginName),
		slog.String("stage", string(in.Stage)),
		slog.Any("error", err),
	)
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, decisionFailedClosed)
	return passThrough(), nil
}

func (p *Plugin) debug(ctx context.Context, msg string, attrs ...any) {
	if p.logger == nil {
		return
	}
	p.logger.DebugContext(ctx, msg, attrs...)
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
