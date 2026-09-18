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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const PluginName = "trustguard"

const (
	directionInput  = "input"
	directionOutput = "output"
	contentTypeJSON = "application/json"
)

const (
	protocolLLM = "llm"
	protocolMCP = "mcp"
	protocolA2A = "a2a"
)

// Stable identifiers for why a leg was not inspected. They go on the event as
// skip_reason so skips can be counted and alerted on, not just read in a log.
const (
	skipReasonNoInspectableInput  = "no_inspectable_input"
	skipReasonNoInspectableOutput = "no_inspectable_output"
	skipReasonEmptyResponseBody   = "empty_response_body"
	skipReasonStreamingMismatch   = "streaming_stage_mismatch"
	skipReasonUnsupportedFormat   = "unsupported_agent_format"
	skipReasonUndecodableResponse = "undecodable_response"
	skipReasonObserveMode         = "observe_mode"
)

const (
	decisionBlocked      = "blocked"
	decisionReported     = "reported"
	decisionAllowed      = "allowed"
	decisionFailedOpen   = "failed_open"
	decisionFailedClosed = "failed_closed"
	decisionTransformed  = "transformed"
	statusBlock          = "block"
	statusReport         = "report"
	statusTransform      = "transform"
	statusAsk            = "ask"
	statusAllow          = "allow"
)

const (
	reasonTransformNoPayload    = "transform_no_payload"
	reasonTransformUnsupported  = "transform_unsupported_path"
	reasonTransformEncodeFailed = "transform_encode_failed"
)

const transformedInputKey = "input"

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	registry *adapter.Registry
	client   *client
	tokens   *tokenManager
	baseURL  string
	logger   *slog.Logger

	cfgCache sync.Map
}

func New(registry *adapter.Registry, baseURL string, timeout time.Duration, clientID, clientSecret string, logger *slog.Logger, opts ...clientOption) *Plugin {
	c := newClient(timeout, opts...)
	return &Plugin{
		registry: registry,
		client:   c,
		tokens:   newTokenManager(c.http, clientID, clientSecret),
		baseURL:  baseURL,
		logger:   logger,
	}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	// Streaming responses become inspectable only after the client drain.
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse, policy.StagePostResponse}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse, policy.StagePostResponse}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM, appplugins.ProtocolMCP}
}

// ScopeInertSafe reports true: TrustGuard inspects the content of a request or
// response. It reads no tool or registry name, so on a plane where the
// mcp_scope does not gate it does exactly what it does on MCP. The scope's
// group stops selecting who it runs for, which means the policy covers all of
// that consumer's traffic — for a content guardrail that is more inspection,
// never less.
func (p *Plugin) ScopeInertSafe() bool { return true }

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) MutatesRequestBody() bool { return true }

func (p *Plugin) MutatesResponseBody() bool { return true }

func (p *Plugin) MutatesMetadata() bool { return false }

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	if !p.tokens.configured() {
		return fmt.Errorf("trustguard: client credentials are not configured (set TRUSTGUARD_CLIENT_ID and TRUSTGUARD_CLIENT_SECRET)")
	}
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := p.config(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("trustguard: %w", err)
	}

	if !cfg.selectsStage(in.Stage) {
		// A leg the policy excludes. Logged because "not inspected" and
		// "inspected, nothing found" are otherwise indistinguishable from the
		// outside: no event, no finding, no trace of the decision anywhere.
		p.debug(ctx, "trustguard leg not selected by policy, skipping",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
			slog.String("direction", cfg.Direction),
		)
		return passThrough(), nil
	}

	baseURL := p.baseURL
	if baseURL == "" {
		p.warn(ctx, "trustguard base url not configured",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
		)
		return passThrough(), nil
	}

	if !p.tokens.configured() {
		p.warn(ctx, "trustguard client credentials not configured, failing open",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
		)
		return passThrough(), nil
	}

	if in.Request == nil {
		return passThrough(), nil
	}
	mcpMode := in.Request.MCP
	if !mcpMode && (p.registry == nil || in.Request.Provider == "") {
		return passThrough(), nil
	}

	direction := directionInput
	if in.Stage == policy.StagePreResponse || in.Stage == policy.StagePostResponse {
		direction = directionOutput
	}

	if strings.TrimSpace(in.Request.GatewayID) == "" {
		p.warn(ctx, "trustguard gateway id missing, failing open",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
			slog.String("direction", direction),
		)
		setExtras(in.Event, guardData{Direction: direction, Decision: decisionFailedOpen, FailedOpen: true})
		return passThrough(), nil
	}

	payload, tgt, skip := p.inspectionPayload(ctx, in, direction, mcpMode)
	if skip {
		return passThrough(), nil
	}

	protocol := protocolFor(in.Request.ConsumerType)
	if mcpMode {
		protocol = protocolMCP
	}
	body := GuardRequest{
		OriginalRequest: requestmeta.FromContext(ctx),
		Payload:         payload,
		Direction:       direction,
		Protocol:        protocol,
		GatewayID:       in.Request.GatewayID,
		SessionID:       in.Request.SessionID,
		ConsumerID:      in.Request.ConsumerID,
		Attributes: GuardAttributes{
			ContentType: contentTypeJSON,
			Model: GuardModel{
				Name:     in.Request.RequestedModel,
				Provider: in.Request.Provider,
			},
			User: principalUser(ctx),
		},
	}

	traceID := gatewayTraceID(ctx)
	playground := requestHasPlaygroundToken(in.Request)
	resp, err := p.guard(ctx, baseURL, cfg.CollectorID, traceID, body, playground)
	if err != nil {
		var limited *rateLimitedError
		if errors.As(err, &limited) {
			setExtras(in.Event, guardData{Direction: direction, Decision: decisionBlocked})
			return nil, rateLimitError(limited)
		}
		var unavailable *entitlementsUnavailableError
		if errors.As(err, &unavailable) {
			setExtras(in.Event, guardData{Direction: direction, Decision: decisionBlocked})
			return nil, unavailableError(unavailable)
		}
		var auth *authRejectedError
		if errors.As(err, &auth) {
			return p.failClosedAuth(ctx, in, direction, err)
		}
		if errors.Is(err, errUnauthorized) {
			return p.failClosedAuth(ctx, in, direction, &authRejectedError{status: http.StatusUnauthorized})
		}
		return p.handleTransportError(ctx, in, cfg, direction, err)
	}

	data := guardData{
		Direction:     direction,
		Status:        resp.Status,
		TraceID:       resp.TraceID,
		RequestID:     resp.RequestID,
		FindingsCount: len(resp.Findings),
		Findings:      resp.Findings,
	}

	if resp.Status == statusTransform {
		return p.applyTransform(ctx, in, data, resp, tgt)
	}

	data.Decision = guardOutcomeDecision(resp.Status, in.Mode)
	if data.Decision == decisionBlocked {
		recordGuardOutcome(in.Event, data)
		return nil, blockError(resp)
	}
	recordGuardOutcome(in.Event, data)
	return passThrough(), nil
}

func (p *Plugin) inspectionPayload(
	ctx context.Context,
	in appplugins.ExecInput,
	direction string,
	mcpMode bool,
) (json.RawMessage, transformTarget, bool) {
	if mcpMode {
		return p.mcpInspectionPayload(ctx, in, direction)
	}
	return p.llmInspectionPayload(ctx, in, direction)
}

func (p *Plugin) mcpInspectionPayload(
	ctx context.Context,
	in appplugins.ExecInput,
	direction string,
) (json.RawMessage, transformTarget, bool) {
	tgt := transformTarget{isResponse: direction == directionOutput}
	if direction == directionInput {
		if len(in.Request.Body) == 0 || strings.TrimSpace(mcpInputText(in.Request.Body)) == "" {
			return p.skipInspection(ctx, in, tgt, direction, skipReasonNoInspectableInput)
		}
		reqBody := in.Request.Body
		toolName := mcpToolName(reqBody)
		tgt.applyPayload = func(payload map[string]any) ([]byte, bool) {
			return mcpTransformedRequest(payload, toolName)
		}
		tgt.apply = func(masked string) ([]byte, bool) { return rewriteMCPRequest(reqBody, masked) }
		payload, err := mcpToolsCallPayload(reqBody)
		if err != nil {
			p.payloadFailure(ctx, in, direction, "trustguard mcp tools/call payload build failed, failing open", err)
			return nil, tgt, true
		}
		return payload, tgt, false
	}
	if reason := outputInspectSkipReason(in.Stage, in.Response); reason != "" {
		return p.skipInspection(ctx, in, tgt, direction, reason)
	}
	if !mcpOutputInspectable(in.Response.Body) {
		// A result with no text anywhere: no text blocks, no embedded resource
		// text, no structuredContent leaves, no tools/list metadata.
		return p.skipInspection(ctx, in, tgt, direction, skipReasonNoInspectableOutput)
	}
	respBody := in.Response.Body
	tgt.applyPayload = mcpTransformedResult
	tgt.apply = func(masked string) ([]byte, bool) { return rewriteMCPResponse(respBody, masked) }
	payload, err := mcpToolsResultPayload(respBody)
	if err != nil {
		p.payloadFailure(ctx, in, direction, "trustguard mcp tools/result payload build failed, failing open", err)
		return nil, tgt, true
	}
	return payload, tgt, false
}

func (p *Plugin) llmInspectionPayload(
	ctx context.Context,
	in appplugins.ExecInput,
	direction string,
) (json.RawMessage, transformTarget, bool) {
	tgt := transformTarget{isResponse: direction == directionOutput}
	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return p.skipInspection(ctx, in, tgt, direction, skipReasonUnsupportedFormat)
	}
	if direction == directionInput {
		if len(in.Request.Body) == 0 {
			return p.skipInspection(ctx, in, tgt, direction, skipReasonNoInspectableInput)
		}
		request, decodeErr := p.registry.DecodeRequestFor(in.Request.Body, format)
		attachments := extractPayloadAttachments(in.Request.Body)
		if decodeErr != nil || request == nil || (strings.TrimSpace(joinRequestText(request)) == "" && len(attachments) == 0) {
			return p.skipInspection(ctx, in, tgt, direction, skipReasonNoInspectableInput)
		}
		tgt.apply = func(masked string) ([]byte, bool) { return rewriteRequest(p.registry, format, request, masked) }
		payload, payloadErr := llmRequestPayloadWithAttachments(request, attachments)
		if payloadErr != nil {
			p.payloadFailure(ctx, in, direction, "trustguard llm payload build failed, failing open", payloadErr)
			return nil, tgt, true
		}
		return payload, tgt, false
	}
	if reason := outputInspectSkipReason(in.Stage, in.Response); reason != "" {
		return p.skipInspection(ctx, in, tgt, direction, reason)
	}
	response, tools := p.canonicalResponse(in, format)
	if response == nil {
		// canonicalResponse swallows the decode error; without this the gateway
		// cannot tell an undecodable response from an empty one.
		return p.skipInspection(ctx, in, tgt, direction, skipReasonUndecodableResponse)
	}
	if !responseHasInspectableContent(response) && len(tools) == 0 {
		return p.skipInspection(ctx, in, tgt, direction, skipReasonNoInspectableOutput)
	}
	if strings.TrimSpace(response.Content) != "" {
		tgt.apply = func(masked string) ([]byte, bool) { return rewriteResponse(p.registry, format, response, masked) }
	}
	payload, payloadErr := llmResponsePayload(response, tools)
	if payloadErr != nil {
		p.payloadFailure(ctx, in, direction, "trustguard llm payload build failed, failing open", payloadErr)
		return nil, tgt, true
	}
	return payload, tgt, false
}

func (p *Plugin) canonicalResponse(in appplugins.ExecInput, format adapter.Format) (*adapter.CanonicalResponse, []adapter.CanonicalTool) {
	var tools []adapter.CanonicalTool
	if request, err := p.registry.DecodeRequestFor(in.Request.Body, format); err == nil && request != nil {
		tools = request.Tools
	}
	if in.Response.Streaming {
		return streamCanonicalResponse(p.registry, in.Response.Body, format), tools
	}
	response, err := p.registry.DecodeResponseFor(in.Response.Body, format)
	if err != nil {
		return nil, tools
	}
	return response, tools
}

// skipInspection records a leg the plugin decided not to inspect, and returns
// the triple the inspection-payload builders use to say "nothing to send".
//
// Every early return in those builders funnels through here on purpose. A skip
// that reports nothing is indistinguishable from an inspection that found
// nothing: same empty findings, same absent event, nothing in Activity or in
// the gateway trace. That is the property that let response-side coverage lapse
// without anyone noticing, so the fix is to make every skip say so.
func (p *Plugin) skipInspection(
	ctx context.Context,
	in appplugins.ExecInput,
	tgt transformTarget,
	direction, reason string,
) (json.RawMessage, transformTarget, bool) {
	p.debug(ctx, "trustguard leg not inspected, skipping",
		slog.String("plugin", PluginName),
		slog.String("stage", string(in.Stage)),
		slog.String("direction", direction),
		slog.String("reason", reason),
	)
	setExtras(in.Event, guardData{Direction: direction, Skipped: true, SkipReason: reason})
	return nil, tgt, true
}

func (p *Plugin) payloadFailure(ctx context.Context, in appplugins.ExecInput, direction, message string, err error) {
	p.warn(ctx, message, slog.String("plugin", PluginName), slog.Any("error", err))
	setExtras(in.Event, guardData{Direction: direction, Decision: decisionFailedOpen, FailedOpen: true})
}

func (p *Plugin) applyTransform(
	ctx context.Context,
	in appplugins.ExecInput,
	data guardData,
	resp *GuardResponse,
	tgt transformTarget,
) (*appplugins.Result, error) {
	if !appplugins.Blocks(in.Mode) {
		if tgt.apply != nil || tgt.applyPayload != nil {
			// The guard asked for a transform and the mode will not apply it,
			// so the content the detector flagged reaches the caller as it
			// was. The event already says "reported"; this says what that cost.
			p.debug(ctx, "trustguard transform not applied in observe mode, forwarding unmasked",
				slog.String("plugin", PluginName),
				slog.String("stage", string(in.Stage)),
				slog.String("direction", data.Direction),
				slog.String("reason", skipReasonObserveMode),
			)
		}
		data.Decision = decisionReported
		recordGuardOutcome(in.Event, data)
		return passThrough(), nil
	}

	// Preserve the structured MCP envelope instead of splitting joined text.
	if tgt.applyPayload != nil {
		if body, ok := tgt.applyPayload(resp.TransformedPayload); ok {
			return p.transformApplied(in, data, tgt, body)
		}
	}

	masked, ok := transformedInput(resp.TransformedPayload)
	if !ok {
		return p.transformDegraded(in, data, resp, reasonTransformNoPayload)
	}
	if tgt.apply == nil {
		return p.transformDegraded(in, data, resp, reasonTransformUnsupported)
	}
	body, ok := tgt.apply(masked)
	if !ok {
		return p.transformDegraded(in, data, resp, reasonTransformEncodeFailed)
	}
	return p.transformApplied(in, data, tgt, body)
}

func (p *Plugin) transformApplied(in appplugins.ExecInput, data guardData, tgt transformTarget, body []byte) (*appplugins.Result, error) {
	data.Decision = decisionTransformed
	recordGuardOutcome(in.Event, data)
	if tgt.isResponse {
		return &appplugins.Result{StatusCode: http.StatusOK, Body: body, StopUpstream: true}, nil
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
}

func (p *Plugin) transformDegraded(in appplugins.ExecInput, data guardData, resp *GuardResponse, reason string) (*appplugins.Result, error) {
	data.Decision = decisionBlocked
	data.Degraded = true
	data.DegradedReason = reason
	recordGuardOutcome(in.Event, data)
	return nil, blockError(resp)
}

func guardOutcomeDecision(status string, mode policy.Mode) string {
	switch status {
	case statusBlock, statusAsk:
		if appplugins.Blocks(mode) {
			return decisionBlocked
		}
		return decisionReported
	case statusReport:
		return decisionReported
	case statusAllow, "":
		return decisionAllowed
	default:
		return decisionReported
	}
}

func (p *Plugin) config(settings map[string]any) (Settings, error) {
	key := configCacheKey(settings)
	if v, ok := p.cfgCache.Load(key); ok {
		return v.(Settings), nil
	}
	cfg, err := parseConfig(settings)
	if err != nil {
		return Settings{}, err
	}
	p.cfgCache.Store(key, cfg)
	return cfg, nil
}

func configCacheKey(settings map[string]any) string {
	return fmt.Sprintf(
		"%v\x00%v\x00%v",
		settings["direction"],
		settings["collector_id"],
		settings["on_error"],
	)
}

func gatewayTraceID(ctx context.Context) string {
	rt := trace.FromContext(ctx)
	if rt == nil {
		return ""
	}
	return rt.TraceID()
}

func principalUser(ctx context.Context) *GuardUser {
	rt := trace.FromContext(ctx)
	if rt == nil {
		return nil
	}
	meta := rt.Metadata()
	id := strings.TrimSpace(meta.PrincipalSubject)
	email := strings.TrimSpace(meta.PrincipalEmail)
	if id == "" && email == "" {
		return nil
	}
	return &GuardUser{ID: id, Email: email}
}

func requestHasPlaygroundToken(req *infracontext.RequestContext) bool {
	if req == nil {
		return false
	}
	for key, values := range req.Headers {
		if !strings.EqualFold(key, "x-ag-playground-token") {
			continue
		}
		for _, v := range values {
			if v != "" {
				return true
			}
		}
	}
	return false
}

func (p *Plugin) guard(ctx context.Context, baseURL, collectorID, traceID string, body GuardRequest, playground bool) (*GuardResponse, error) {
	params := tokenParams{
		baseURL:     baseURL,
		collectorID: collectorID,
		gatewayID:   body.GatewayID,
	}
	token, err := p.tokens.token(ctx, params)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Guard(ctx, baseURL, token, traceID, body, playground)
	if err == nil {
		return resp, nil
	}
	if !errors.Is(err, errUnauthorized) {
		return nil, err
	}
	p.tokens.invalidate(params)
	token, err = p.tokens.token(ctx, params)
	if err != nil {
		return nil, err
	}
	resp, err = p.client.Guard(ctx, baseURL, token, traceID, body, playground)
	if err == nil {
		return resp, nil
	}
	if errors.Is(err, errUnauthorized) {
		return nil, &authRejectedError{status: http.StatusUnauthorized}
	}
	return nil, err
}

func (p *Plugin) failClosedAuth(ctx context.Context, in appplugins.ExecInput, direction string, err error) (*appplugins.Result, error) {
	recordEvaluateFailure(ctx, failureReasonUnauthorized)
	p.error(ctx, "trustguard auth/config rejected, failing closed",
		slog.String("plugin", PluginName),
		slog.String("stage", string(in.Stage)),
		slog.String("direction", direction),
		slog.Any("error", err),
	)
	var auth *authRejectedError
	if !errors.As(err, &auth) {
		auth = &authRejectedError{status: http.StatusUnauthorized}
	}
	data := guardData{
		Direction:     direction,
		Decision:      decisionFailedClosed,
		FailedClosed:  true,
		FailureReason: failureReasonUnauthorized,
	}
	recordGuardOutcome(in.Event, data)
	return nil, unauthorizedError(auth)
}

func (p *Plugin) handleTransportError(ctx context.Context, in appplugins.ExecInput, cfg Settings, direction string, err error) (*appplugins.Result, error) {
	if cfg.failClosedOnTransport() {
		recordEvaluateFailure(ctx, failureReasonTransport)
		p.error(ctx, "trustguard call failed, failing closed",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
			slog.String("direction", direction),
			slog.Any("error", err),
		)
		data := guardData{
			Direction:     direction,
			Decision:      decisionFailedClosed,
			FailedClosed:  true,
			FailureReason: failureReasonTransport,
		}
		recordGuardOutcome(in.Event, data)
		return nil, transportFailClosedError()
	}
	p.warn(ctx, "trustguard call failed, failing open",
		slog.String("plugin", PluginName),
		slog.String("stage", string(in.Stage)),
		slog.String("direction", direction),
		slog.Any("error", err),
	)
	setExtras(in.Event, guardData{Direction: direction, Decision: decisionFailedOpen, FailedOpen: true})
	return passThrough(), nil
}

func (p *Plugin) warn(ctx context.Context, msg string, attrs ...any) {
	if p.logger == nil {
		return
	}
	p.logger.WarnContext(ctx, msg, attrs...)
}

func (p *Plugin) debug(ctx context.Context, msg string, attrs ...any) {
	if p.logger == nil {
		return
	}
	p.logger.DebugContext(ctx, msg, attrs...)
}

func (p *Plugin) error(ctx context.Context, msg string, attrs ...any) {
	if p.logger == nil {
		return
	}
	p.logger.ErrorContext(ctx, msg, attrs...)
}

func protocolFor(consumerType string) string {
	switch strings.ToLower(strings.TrimSpace(consumerType)) {
	case protocolMCP:
		return protocolMCP
	case protocolA2A:
		return protocolA2A
	default:
		return protocolLLM
	}
}

// outputInspectSkipReason returns why this response leg is not inspected, or ""
// when it is. It replaces a bool so the two very different causes — there was no
// body at all, versus this stage does not handle this streaming mode — stop
// being reported as the same thing. Behaviour is unchanged; only the caller's
// ability to say why is new.
func outputInspectSkipReason(stage policy.Stage, resp *infracontext.ResponseContext) string {
	if resp == nil || len(resp.Body) == 0 {
		return skipReasonEmptyResponseBody
	}
	switch stage {
	case policy.StagePreResponse:
		if resp.Streaming {
			return skipReasonStreamingMismatch
		}
	case policy.StagePostResponse:
		if !resp.Streaming {
			return skipReasonStreamingMismatch
		}
	default:
		return skipReasonStreamingMismatch
	}
	return ""
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
