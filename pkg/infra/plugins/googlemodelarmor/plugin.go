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
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "google_model_armor"

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

// rewriteSpan carries what runGuardrail needs to reinject masked text into
// either leg of the exchange without knowing which one it is.
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

// Plugin is the google_model_armor guardrail: a single Model Armor sanitize
// call per stage, with block_on picking which of its orthogonal findings
// (sdp, rai, pi_and_jailbreak, malicious_uris, csam) blocks the request.
// Streaming responses and multimodal content are out of scope: the REST v1
// API this client speaks has no StreamSanitize* method and no DataItem
// support for those endpoints.
type Plugin struct {
	registry *adapter.Registry
	clients  *clientCache
	logger   *slog.Logger
}

// New builds the plugin. baseURL and timeout come from cfg.ModelArmor
// (pkg/config); baseURL is normally empty so the client derives the regional
// host from each call's own location. Authentication is per policy: a
// *client (and the token source it wraps) is built lazily, at most once per
// distinct credentials fingerprint, the first time a policy using that
// credential set runs — see clientFor and Settings.Credentials.
func New(registry *adapter.Registry, baseURL string, timeout time.Duration, logger *slog.Logger) *Plugin {
	return &Plugin{
		registry: registry,
		clients:  newModelArmorClientCache(baseURL, timeout, newCredentialSources()),
		logger:   logger,
	}
}

// clientFor resolves the *client for cfg's credentials, reusing the cached
// client for that credential fingerprint when one already exists.
func (p *Plugin) clientFor(cfg Settings) (*client, error) {
	if p.clients == nil {
		return nil, fmt.Errorf("google_model_armor: plugin has no client cache configured")
	}
	return p.clients.get(credentialsFromConfig(cfg.Credentials))
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
		return nil, fmt.Errorf("google_model_armor: %w", err)
	}
	cl, err := p.clientFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("google_model_armor: %w", err)
	}
	switch in.Stage {
	case policy.StagePreRequest:
		return p.executePreRequest(ctx, in, cfg, cl)
	case policy.StagePreResponse:
		return p.executePreResponse(ctx, in, cfg, cl)
	default:
		return passThrough(), nil
	}
}

// executePreRequest sends only the last user message, like bedrock: Model
// Armor bills per request, so replaying the whole conversation on every turn
// would grow the bill linearly with conversation length.
func (p *Plugin) executePreRequest(ctx context.Context, in appplugins.ExecInput, cfg Settings, cl *client) (*appplugins.Result, error) {
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
	sanitize := func(ctx context.Context) (*SanitizationResult, error) {
		return cl.SanitizeUserPrompt(ctx, cfg.Project, cfg.Location, cfg.Template, text)
	}
	return p.runGuardrail(ctx, in, cfg, sanitize, span)
}

// executePreResponse sanitizes the completion in its own call, separate from
// pre_request, again to keep Model Armor billing to one call per turn per
// stage rather than resending history.
func (p *Plugin) executePreResponse(ctx context.Context, in appplugins.ExecInput, cfg Settings, cl *client) (*appplugins.Result, error) {
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
	userPrompt := correlationPrompt(p.registry, format, in.Request.Body)
	span := rewriteSpan{
		format:     format,
		isResponse: true,
		rewrite: func(masked string) ([]byte, bool) {
			return rewriteResponse(p.registry, format, cresp, masked)
		},
	}
	sanitize := func(ctx context.Context) (*SanitizationResult, error) {
		return cl.SanitizeModelResponse(ctx, cfg.Project, cfg.Location, cfg.Template, text, userPrompt)
	}
	return p.runGuardrail(ctx, in, cfg, sanitize, span)
}

// correlationPrompt best-effort decodes the original request's last user
// message to pass as SanitizeModelResponse's optional userPrompt context.
// Any failure here just omits the correlation; it never blocks the response.
func correlationPrompt(reg *adapter.Registry, format adapter.Format, requestBody []byte) string {
	if reg == nil || len(requestBody) == 0 {
		return ""
	}
	creq, err := reg.DecodeRequestFor(requestBody, format)
	if err != nil || creq == nil {
		return ""
	}
	text, _ := lastUserText(creq)
	return text
}

func (p *Plugin) runGuardrail(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	sanitize func(context.Context) (*SanitizationResult, error),
	span rewriteSpan,
) (*appplugins.Result, error) {
	start := time.Now()
	result, err := sanitize(ctx)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return p.failClosed(ctx, in, cfg, latency, err)
	}
	if result.InvocationResult == invocationResultFailure {
		return p.failClosed(ctx, in, cfg, latency, fmt.Errorf("google_model_armor: invocationResult FAILURE"))
	}
	// A filter we were told to block on that did not actually run reports no
	// match, exactly like a filter that ran and found nothing — and the
	// envelope can still say SUCCESS overall. Take the same path as an
	// outright failure rather than mistake silence for safety.
	if f := unevaluatedFilter(result, cfg.blockOnSet()); f != "" {
		return p.failClosed(ctx, in, cfg, latency,
			fmt.Errorf("google_model_armor: filter %q did not execute", f))
	}

	res := inspect(result, cfg)
	data := newData(in, cfg, latency)
	data.FilterVersion = result.filterVersion()

	if res.block != nil {
		applyFinding(data, res.block)
		recordScore(in.Event, data)
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
		recordScore(in.Event, data)
		if appplugins.Blocks(in.Mode) {
			return p.anonymizeEnforce(in, data, result, span, res.anonymize)
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

func (p *Plugin) anonymizeEnforce(
	in appplugins.ExecInput,
	data *Data,
	result *SanitizationResult,
	span rewriteSpan,
	f *finding,
) (*appplugins.Result, error) {
	masked, ok := maskedText(result)
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

// failClosed is the shared outcome for a transport error or an
// invocationResult of FAILURE: enforce mode rejects the call, observe mode
// passes it through unmodified. Same contract as bedrock_guardrail.
func (p *Plugin) failClosed(ctx context.Context, in appplugins.ExecInput, cfg Settings, latency int64, err error) (*appplugins.Result, error) {
	data := newData(in, cfg, latency)
	data.Decision = decisionFailedClosed
	if appplugins.Blocks(in.Mode) {
		p.debug(ctx, "model armor call failed, failing closed",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
			slog.Any("error", err),
		)
		setExtras(in.Event, data)
		return nil, fmt.Errorf("google_model_armor: sanitize: %w", err)
	}
	p.debug(ctx, "model armor call failed, observe mode passing through",
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
		Project:   cfg.Project,
		Location:  cfg.Location,
		Template:  cfg.Template,
		Stage:     string(in.Stage),
		Mode:      string(in.Mode),
		LatencyMS: latency,
	}
}

func applyFinding(data *Data, f *finding) {
	data.Filter = f.filter
	data.InfoTypes = f.infoTypes
	data.Confidence = f.confidence
	data.Category = f.category
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
