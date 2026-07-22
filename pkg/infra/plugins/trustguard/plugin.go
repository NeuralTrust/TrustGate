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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
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

const (
	decisionBlocked     = "blocked"
	decisionReported    = "reported"
	decisionAllowed     = "allowed"
	decisionFailedOpen  = "failed_open"
	decisionTransformed = "transformed"
	statusBlock         = "block"
	statusReport        = "report"
	statusTransform     = "transform"
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

func New(registry *adapter.Registry, baseURL string, timeout time.Duration, clientID, clientSecret string, logger *slog.Logger) *Plugin {
	c := newClient(timeout)
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
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM, appplugins.ProtocolMCP}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

// MutatesRequestBody reports that TrustGuard may rewrite the request body when
// TrustGuard returns a transform (data-masking) outcome. Declaring this keeps
// the plugin out of parallel batches with other body writers so the masked body
// is applied deterministically and downstream plugins observe it.
func (p *Plugin) MutatesRequestBody() bool { return true }

// MutatesResponseBody reports that TrustGuard may rewrite the response body when
// TrustGuard returns a transform (data-masking) outcome. See MutatesRequestBody
// for why this forces sequential execution.
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
	if in.Stage == policy.StagePreResponse {
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

	var text string
	tgt := transformTarget{isResponse: direction == directionOutput}
	if mcpMode {
		if direction == directionInput {
			if len(in.Request.Body) == 0 {
				return passThrough(), nil
			}
			text = mcpInputText(in.Request.Body)
		} else {
			if in.Response == nil || in.Response.Streaming || len(in.Response.Body) == 0 {
				return passThrough(), nil
			}
			text = mcpOutputText(in.Response.Body)
		}
	} else {
		format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
		if err != nil {
			return passThrough(), nil
		}
		if direction == directionInput {
			if len(in.Request.Body) == 0 {
				return passThrough(), nil
			}
			creq, decErr := p.registry.DecodeRequestFor(in.Request.Body, format)
			if decErr != nil || creq == nil {
				return passThrough(), nil
			}
			text = joinRequestText(creq)
			reg := p.registry
			tgt.apply = func(masked string) ([]byte, bool) {
				return rewriteRequest(reg, format, creq, masked)
			}
		} else {
			if in.Response == nil || in.Response.Streaming || len(in.Response.Body) == 0 {
				return passThrough(), nil
			}
			cresp, decErr := p.registry.DecodeResponseFor(in.Response.Body, format)
			if decErr != nil || cresp == nil {
				return passThrough(), nil
			}
			text = cresp.Content
			reg := p.registry
			tgt.apply = func(masked string) ([]byte, bool) {
				return rewriteResponse(reg, format, cresp, masked)
			}
		}
	}
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}

	protocol := protocolFor(in.Request.ConsumerType)
	if mcpMode {
		protocol = protocolMCP
	}
	body := GuardRequest{
		Payload:    GuardPayload{Input: text},
		Direction:  direction,
		Protocol:   protocol,
		GatewayID:  in.Request.GatewayID,
		SessionID:  in.Request.SessionID,
		ConsumerID: in.Request.ConsumerID,
		Attributes: GuardAttributes{
			ContentType: contentTypeJSON,
			Model: GuardModel{
				Name:     in.Request.RequestedModel,
				Provider: in.Request.Provider,
			},
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
		p.warn(ctx, "trustguard call failed, failing open",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
			slog.String("direction", direction),
			slog.Any("error", err),
		)
		setExtras(in.Event, guardData{Direction: direction, Decision: decisionFailedOpen, FailedOpen: true})
		return passThrough(), nil
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
		return p.applyTransform(in, data, resp, tgt)
	}

	data.Decision = guardOutcomeDecision(resp.Status, in.Mode)
	if data.Decision == decisionBlocked {
		recordGuardOutcome(in.Event, data)
		return nil, blockError(resp)
	}
	recordGuardOutcome(in.Event, data)
	return passThrough(), nil
}

// applyTransform enforces a TrustGuard transform (data-masking) outcome. In
// observe mode the masked body is not applied and the outcome is reported. In
// enforce mode the masked payload is written back into the provider body; when
// it cannot be applied safely (missing payload, path without body propagation,
// or re-encode failure) the request is blocked rather than forwarding the
// unmasked data upstream.
func (p *Plugin) applyTransform(in appplugins.ExecInput, data guardData, resp *GuardResponse, tgt transformTarget) (*appplugins.Result, error) {
	if !appplugins.Blocks(in.Mode) {
		data.Decision = decisionReported
		recordGuardOutcome(in.Event, data)
		return passThrough(), nil
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
	case statusBlock:
		if appplugins.Blocks(mode) {
			return decisionBlocked
		}
		return decisionReported
	case statusReport:
		return decisionReported
	default:
		return decisionAllowed
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
	return fmt.Sprintf("%v\x00%v", settings["inspect"], settings["collector_id"])
}

func gatewayTraceID(ctx context.Context) string {
	rt := trace.FromContext(ctx)
	if rt == nil {
		return ""
	}
	return rt.TraceID()
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
	return p.client.Guard(ctx, baseURL, token, traceID, body, playground)
}

func (p *Plugin) warn(ctx context.Context, msg string, attrs ...any) {
	if p.logger == nil {
		return
	}
	p.logger.WarnContext(ctx, msg, attrs...)
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

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
