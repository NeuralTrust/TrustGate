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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
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
	// skipReasonProviderNotStreaming marks a response leg that opted into
	// per-block inspection and never got a block to inspect: the provider
	// produced no stream the guard could close a block on. Without it the
	// event is indistinguishable from a stream that was inspected and found
	// clean, which is the same gap skipReasonEmptyResponseBody closed on the
	// buffered leg.
	skipReasonProviderNotStreaming = "provider_not_streaming"
	// skipReasonInspectedAsStream marks the pre_response leg of a streamed
	// LLM response whose policy opted into per-block inspection, decided from
	// the policy settings at pre_response time. That leg runs when only the
	// headers have arrived, so it has nothing to read by design: the response
	// is handed to the stream guard, which writes its own entry, and is
	// audited once more after the drain. It is not a coverage gap, and it must
	// not read as one ("the response had no body").
	//
	// Residual gap, dormant: if an earlier pre_response plugin errors or
	// short-circuits a streamed leg, finalizeStream drains without building
	// the guard, so the label would be optimistic. No plugin produces that on
	// a stream today.
	skipReasonInspectedAsStream = "inspected_as_stream"
	// skipReasonStreamCut marks the post_response leg of a stream the stream
	// guard cut mid-way. What was delivered ends on the cut terminator and
	// nothing after the cut reached the client; the guard's own entry already
	// says "blocked". Inspecting the truncated body again would only record
	// "allowed" right after it, so the leg is skipped. Not a coverage gap.
	skipReasonStreamCut = "stream_cut"
)

// Why a streamed leg stopped being inspected the way the policy asked. The
// values are the shared tokens: the guard records them and this plugin
// publishes them, and they land in ClickHouse, so a rename after release is a
// data migration rather than a code change.
const (
	degradedReasonAccumulationCap     = appplugins.StreamDegradeAccumulationCap
	degradedReasonGuardTimeout        = appplugins.StreamDegradeGuardTimeout
	degradedReasonGuardError          = appplugins.StreamDegradeGuardError
	fallbackReasonSegmentationUnavail = appplugins.StreamFallbackSegmentationUnavail
	fallbackReasonClientDisconnected  = appplugins.StreamFallbackClientDisconnected
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

var (
	_ appplugins.Plugin          = (*Plugin)(nil)
	_ appplugins.StreamInspector = (*Plugin)(nil)
)

type Plugin struct {
	registry *adapter.Registry
	client   *client
	tokens   *tokenManager
	baseURL  string
	logger   *slog.Logger
	// timeout is the deployment-wide deadline of an evaluate call whose
	// policy sets none. A policy can shorten or lengthen its own calls
	// without every gateway sharing the change.
	timeout time.Duration

	cfgCache sync.Map

	// streamFailures holds, per stream and policy, a *streamFailure: why the
	// last failed-open block went through uninspected, and how many failed in
	// a row. The closing segment publishes it and takes it out; entries a
	// closing never reached expire after streamFailureTTL.
	streamFailures sync.Map
	streamSweptAt  atomic.Int64

	// streamBlocks holds, per stream and policy, a *streamPosition: how many
	// evaluates were sent for it so far. It is keyed like streamFailures, the
	// closing segment takes it out, and entries a closing never reached expire
	// after streamFailureTTL.
	streamBlocks        sync.Map
	streamBlocksSweptAt atomic.Int64
}

func New(registry *adapter.Registry, baseURL string, timeout time.Duration, clientID, clientSecret string, logger *slog.Logger, opts ...clientOption) *Plugin {
	c := newClient(timeout, opts...)
	// The token client keeps the deployment-wide timeout: its fetch is shared
	// through singleflight and runs detached from every caller's deadline
	// (see fetchOnce), so the client timeout is the only bound it has.
	tokenHTTP := &http.Client{Timeout: timeout, Transport: c.http.Transport}
	return &Plugin{
		registry: registry,
		client:   c,
		tokens:   newTokenManager(tokenHTTP, clientID, clientSecret),
		baseURL:  baseURL,
		logger:   logger,
		timeout:  timeout,
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

// BedrockNative declares what the plugin does on a native Amazon Bedrock Runtime
// call (see appplugins.BedrockNativeAware).
func (p *Plugin) BedrockNative() appplugins.BedrockNativeBehavior {
	return appplugins.BedrockNativeMasks
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	if !p.tokens.configured() {
		return fmt.Errorf("trustguard: client credentials are not configured (set TRUSTGUARD_CLIENT_ID and TRUSTGUARD_CLIENT_SECRET)")
	}
	_, err := parseConfig(settings)
	return err
}

var _ appplugins.SettingsWriteValidator = (*Plugin)(nil)

// ValidateSettingsWrite rejects a new streaming.final_pass: false, which the
// block loop cannot honour (pluginutil.ValidateFinalPassWrite).
func (p *Plugin) ValidateSettingsWrite(settings, previous map[string]any) error {
	return pluginutil.ValidateFinalPassWrite(PluginName, settings, previous)
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := p.config(in.Config.Settings)
	if err != nil {
		// Settings that do not parse carry no on_error to honour, so the
		// failure resolves the default way.
		return p.guardFailure(ctx, in, stageDirection(in.Stage), failureReasonConfigInvalid, false, nil, err)
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

	if in.Request == nil {
		return passThrough(), nil
	}
	mcpMode := in.Request.MCP
	if !mcpMode && (p.registry == nil || in.Request.Provider == "") {
		return passThrough(), nil
	}

	direction := stageDirection(in.Stage)

	if strings.TrimSpace(in.Request.GatewayID) == "" {
		return p.guardFailure(ctx, in, direction, failureReasonGatewayIDMissing, false, nil, nil)
	}

	payload, tgt, skip := p.inspectionPayload(ctx, in, direction, mcpMode)
	if skip {
		return passThrough(), nil
	}

	// A pod that cannot reach TrustGuard at all — no URL, no credentials: a
	// Secret that did not mount, a partial rollout, a hybrid data plane that
	// received the policy through config sync without the environment — is a
	// failure of the guard, not a finding, so it follows on_error like any
	// other. Checked only once there is something to inspect, so the failure
	// count is the traffic that actually went through uninspected.
	baseURL := p.baseURL
	if baseURL == "" {
		return p.guardFailure(ctx, in, direction, failureReasonBaseURLMissing, cfg.failClosedOnTransport(), notConfiguredError(), nil)
	}
	if !p.tokens.configured() {
		return p.guardFailure(ctx, in, direction, failureReasonCredentialsMissing, cfg.failClosedOnTransport(), notConfiguredError(), nil)
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
			User:     principalUser(ctx),
			Consumer: guardConsumer(in.Request.ConsumerID, in.Request.ConsumerName),
		},
	}

	traceID := gatewayTraceID(ctx)
	playground := requestHasPlaygroundToken(in.Request)
	// The deadline is set here rather than left to the HTTP client so that a
	// policy can carry its own, and so that a call that runs out of time is
	// reported as a timeout rather than as an indistinguishable transport
	// error. The client's own Timeout is only a backstop above any deadline
	// a policy is allowed to set.
	callCtx, cancel := context.WithTimeout(ctx, cfg.timeoutOr(p.timeout))
	defer cancel()
	resp, err := p.guard(callCtx, baseURL, cfg.CollectorID, traceID, body, playground)
	if err != nil {
		var limited *rateLimitedError
		if errors.As(err, &limited) {
			setExtras(in.Event, guardData{Direction: direction, Decision: decisionBlocked})
			return nil, rateLimitError(limited)
		}
		var unavailable *entitlementsUnavailableError
		if errors.As(err, &unavailable) {
			return p.guardFailure(ctx, in, direction, failureReasonEntitlementsUnavailable, cfg.failClosedOnTransport(), unavailableError(unavailable), err)
		}
		var auth *authRejectedError
		if errors.As(err, &auth) {
			return p.guardFailure(ctx, in, direction, failureReasonUnauthorized, cfg.failClosedOnTransport(), unauthorizedError(auth), err)
		}
		if errors.Is(err, errUnauthorized) {
			return p.guardFailure(ctx, in, direction, failureReasonUnauthorized, cfg.failClosedOnTransport(),
				unauthorizedError(&authRejectedError{status: http.StatusUnauthorized}), err)
		}
		// The caller's own cancellation is not ours to reinterpret: only a
		// deadline this call imposed counts as the guard running out of time.
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return p.guardFailure(ctx, in, direction, failureReasonTimeout, cfg.failClosedOnTimeout(), timeoutFailClosedError(), err)
		}
		return p.guardFailure(ctx, in, direction, failureReasonTransport, cfg.failClosedOnTransport(), transportFailClosedError(), err)
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
		return p.applyTransform(ctx, in, cfg, data, resp, tgt)
	}

	data.Decision = guardOutcomeDecision(resp.Status, in.Mode)
	if data.Decision == decisionBlocked {
		recordGuardOutcome(in.Event, data)
		return nil, blockError(resp, direction)
	}
	recordGuardOutcome(in.Event, data)
	return passThrough(), nil
}

// InspectSegment evaluates one closed block of a streaming response leg and
// returns the verdict for it. It is the streaming counterpart of Execute's
// output leg and leaves Execute untouched: the buffered path keeps calling the
// guard once per response.
//
// Ownership of streaming.on_error: the caller owns it, this plugin never reads
// it. The setting decides what happens to text the caller is holding — release
// it and degrade, or cut — and only the caller knows how much is held, whether
// the head block is still uncommitted, and how many blocks in a row have
// failed. Applying it here as well would apply it twice. So a failure whose
// handling is configurable comes back as an error and the caller resolves it.
//
// Two exceptions. A 429 is the engine answering, and comes back as a blocking
// verdict whatever streaming.on_error says. And a failure of TrustGuard itself
// — transport, rejected or missing credentials, no base URL, unavailable
// entitlements, a mask that cannot be applied — is resolved here when
// streaming.on_error is fail_open: the block is allowed and the failure is
// published on the stream's span at closing. Returning it as an error instead
// would stop the executor from running the rest of the chain on that block, and
// after a few in a row retire inspection for every plugin on the stream, so one
// broken guard would switch off the others. Under fail_closed it goes back as an
// error and the caller cuts.
//
// Mode is likewise not applied here. A block verdict is what the engine said;
// the executor downgrades it to a report for an observe-mode entry.
func (p *Plugin) InspectSegment(
	ctx context.Context,
	in appplugins.ExecInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentVerdict, error) {
	return p.inspectSegment(ctx, in, seg)
}

// StreamSettings reports whether these policy settings enable per-block
// inspection of the response leg, and the options the caller must run the
// stream under. Implementing InspectSegment is not the opt-in on its own: this
// plugin is on every pre_response chain that names it, and a policy can opt
// out with streaming.enabled: false or by not selecting the response leg, so
// without this the head gate would be built for policies that turned it off.
//
// head_chars and streaming.on_error come back with the opt-in because this
// settings map is this plugin's schema. Settings that fail to parse disable
// the stream leg here; the buffered legs surface the same error where they
// already do.
func (p *Plugin) StreamSettings(settings map[string]any) (bool, appplugins.StreamOptions) {
	// No shortcut on an absent "streaming" key: absent means on, with the
	// defaults. p.config is cached by a digest of the settings map, so the
	// repeat cost on every streamed request is one digest, not a parse.
	cfg, err := p.config(settings)
	if err != nil {
		return false, appplugins.StreamOptions{}
	}
	if !cfg.Streaming.enabled() || !cfg.selectsStage(policy.StagePreResponse) {
		return false, appplugins.StreamOptions{}
	}
	return true, appplugins.StreamOptions{
		HeadChars:            cfg.Streaming.HeadChars,
		OnError:              cfg.Streaming.OnError,
		MinCharsBetweenEvals: cfg.Streaming.MinCharsBetweenEvals,
		MaxHoldMS:            cfg.Streaming.MaxHoldMS,
		MaxAccumulatedBytes:  cfg.Streaming.MaxAccumulatedBytes,
	}
}

// streamGuardOwns reports whether this policy's streamed response is inspected
// block by block, so its header-only pre_response leg has nothing left to do.
func (p *Plugin) streamGuardOwns(in appplugins.ExecInput) bool {
	enabled, _ := p.StreamSettings(in.Config.Settings)
	return enabled
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
	// An MCP response never reaches the stream guard (the MCP runner buffers
	// the result), so it is never labelled as one.
	if reason := outputInspectSkipReason(in.Stage, in.Response, false); reason != "" {
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
		if adapter.IsRequestDecodeError(decodeErr) && adapter.IsChatRequest(in.Request.ProxyCapability, format) {
			p.payloadFailure(ctx, in, direction, "trustguard request body decode failed, failing open", decodeErr)
			return nil, tgt, true
		}
		if request != nil && request.DroppedInputItems > 0 {
			p.debug(ctx, "trustguard request input items left out of inspection",
				slog.String("plugin", PluginName),
				slog.Int("dropped_items", request.DroppedInputItems),
			)
		}
		attachments := extractPayloadAttachments(in.Request.Body)
		if decodeErr != nil || request == nil || (strings.TrimSpace(joinRequestText(request)) == "" && len(attachments) == 0) {
			return p.skipInspection(ctx, in, tgt, direction, skipReasonNoInspectableInput)
		}
		original := in.Request.Body
		// No string fallback: a messages[] echo that does not map by position
		// must fail closed, not be re-split by line count and written into
		// whichever message the lines land in. The legacy "input" string is
		// still honoured here.
		tgt.applyPayload = func(payload map[string]any) ([]byte, bool) {
			if masked, ok := payload[transformedInputKey].(string); ok {
				return rewriteRequest(p.registry, format, original, request, masked)
			}
			return rewriteRequestFromMessages(p.registry, format, original, request, payload)
		}
		payload, payloadErr := llmRequestPayloadWithAttachments(request, attachments)
		if payloadErr != nil {
			p.payloadFailure(ctx, in, direction, "trustguard llm payload build failed, failing open", payloadErr)
			return nil, tgt, true
		}
		return payload, tgt, false
	}
	if reason := outputInspectSkipReason(in.Stage, in.Response, p.streamGuardOwns(in)); reason != "" {
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
	// The arguments of a tool call travel only in the messages echo, so with
	// calls present a text-only fallback would forward them unmasked.
	if strings.TrimSpace(response.Content) != "" && len(response.ToolCalls) == 0 {
		tgt.apply = func(masked string) ([]byte, bool) { return rewriteResponse(p.registry, format, response, masked) }
	}
	tgt.applyPayload = func(payload map[string]any) ([]byte, bool) {
		return rewriteResponseFromPayload(p.registry, format, response, payload)
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
	recordEvaluateFailure(ctx, failureReasonPayloadUnreadable)
	p.warn(ctx, message, slog.String("plugin", PluginName), slog.Any("error", err))
	recordGuardOutcome(in.Event, guardData{
		Direction:     direction,
		Decision:      decisionFailedOpen,
		FailedOpen:    true,
		FailureReason: failureReasonPayloadUnreadable,
	})
}

func (p *Plugin) applyTransform(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
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

	// Map the structured payload (MCP envelope, LLM messages[]) back by
	// position instead of splitting joined text.
	if tgt.applyPayload != nil {
		if body, ok := tgt.applyPayload(resp.TransformedPayload); ok {
			return p.transformApplied(in, data, tgt, body)
		}
		if tgt.apply == nil {
			if _, ok := transformedInput(resp.TransformedPayload); !ok {
				return p.transformDegraded(ctx, in, cfg, data, resp, reasonTransformNoPayload)
			}
			return p.transformDegraded(ctx, in, cfg, data, resp, reasonTransformEncodeFailed)
		}
	}

	masked, ok := transformedInput(resp.TransformedPayload)
	if !ok {
		return p.transformDegraded(ctx, in, cfg, data, resp, reasonTransformNoPayload)
	}
	if tgt.apply == nil {
		return p.transformDegraded(ctx, in, cfg, data, resp, reasonTransformUnsupported)
	}
	body, ok := tgt.apply(masked)
	if !ok {
		return p.transformDegraded(ctx, in, cfg, data, resp, reasonTransformEncodeFailed)
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

// transformDegraded is TrustGuard asking for content to be masked and this
// plugin being unable to write the mask back. That is a failure on our side,
// not a finding the guard missed, so it follows on_error like any other
// failure: by default the original content goes on, unmasked, and the span
// says so and why; a policy that opted into fail_closed blocks it instead.
func (p *Plugin) transformDegraded(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	data guardData,
	resp *GuardResponse,
	reason string,
) (*appplugins.Result, error) {
	recordEvaluateFailure(ctx, failureReasonTransformFailed)
	data.Degraded = true
	data.DegradedReason = reason
	data.FailureReason = failureReasonTransformFailed
	attrs := []any{
		slog.String("plugin", PluginName),
		slog.String("stage", string(in.Stage)),
		slog.String("direction", data.Direction),
		slog.String("reason", reason),
	}
	if cfg.failClosedOnTransport() {
		// TrustGuard did find something, so a policy that opted into
		// fail_closed gets the block it always got, finding and all.
		p.error(ctx, "trustguard transform could not be applied, blocking", attrs...)
		data.Decision = decisionBlocked
		data.FailureReason = ""
		recordGuardOutcome(in.Event, data)
		return nil, blockError(resp, data.Direction)
	}
	p.warn(ctx, "trustguard transform could not be applied, forwarding unmasked", attrs...)
	data.Decision = decisionFailedOpen
	data.FailedOpen = true
	recordGuardOutcome(in.Event, data)
	return passThrough(), nil
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
	key, cacheable := configCacheKey(settings)
	if cacheable {
		if v, ok := p.cfgCache.Load(key); ok {
			return v.(Settings), nil
		}
	}
	cfg, err := parseConfig(settings)
	if err != nil {
		return Settings{}, err
	}
	if cacheable {
		p.cfgCache.Store(key, cfg)
	}
	return cfg, nil
}

// configCacheKey digests the whole settings map, so a setting added to
// Settings later is part of the key the day it is added. Naming individual
// keys made every other one invisible on an already-parsed policy until the
// process restarted. It reports false when the map does not marshal, in which
// case the caller must bypass the cache rather than share an entry with a
// different config.
func configCacheKey(settings map[string]any) (string, bool) {
	raw, err := json.Marshal(settings)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), true
}

func gatewayTraceID(ctx context.Context) string {
	rt := trace.FromContext(ctx)
	if rt == nil {
		return ""
	}
	return rt.TraceID()
}

// guardConsumer is the application a request came from, or nil when it is not
// known.
func guardConsumer(id, name string) *GuardConsumer {
	id, name = strings.TrimSpace(id), strings.TrimSpace(name)
	if id == "" && name == "" {
		return nil
	}
	return &GuardConsumer{ID: id, Name: name}
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
	return p.guardWith(ctx, p.tokens.token, baseURL, collectorID, traceID, body, playground)
}

// guardWith runs one evaluate call, retrying once with a fresh token after a
// 401. The token leg comes from the caller because the two paths fetch it
// differently: a streamed block holding bytes back cannot wait out a cold
// token the way a buffered call can, so it passes tokenWithin.
//
// Both evaluate legs share one deadline from the caller, so a retry spends
// what is left of it instead of a budget of its own. The token leg is held to
// that deadline only on the streaming path (tokenWithin); the buffered path
// waits for the shared fetch, which the token client's own timeout bounds.
func (p *Plugin) guardWith(
	ctx context.Context,
	fetchToken tokenSource,
	baseURL, collectorID, traceID string,
	body GuardRequest,
	playground bool,
) (*GuardResponse, error) {
	params := tokenParams{
		baseURL:     baseURL,
		collectorID: collectorID,
		gatewayID:   body.GatewayID,
	}
	token, err := fetchToken(ctx, params)
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
	token, err = fetchToken(ctx, params)
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

func stageDirection(stage policy.Stage) string {
	if stage == policy.StagePreResponse || stage == policy.StagePostResponse {
		return directionOutput
	}
	return directionInput
}

// guardFailure resolves every failure of the guard itself — as opposed to a
// finding — the same way: the request carries on unless the policy opted into
// failing closed, and it never carries on silently. The metric counts it and
// the span carries failed_open with the reason, which is what the console
// reads. A deliberate answer (a block, a 429) is not a failure and never comes
// here. closed is only used when failClosed is set.
func (p *Plugin) guardFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	direction string,
	reason string,
	failClosed bool,
	closed *appplugins.PluginError,
	err error,
) (*appplugins.Result, error) {
	recordEvaluateFailure(ctx, reason)
	attrs := []any{
		slog.String("plugin", PluginName),
		slog.String("stage", string(in.Stage)),
		slog.String("direction", direction),
		slog.String("reason", reason),
	}
	if err != nil {
		attrs = append(attrs, slog.Any("error", err))
	}
	if failClosed {
		p.error(ctx, "trustguard could not inspect, failing closed", attrs...)
		recordGuardOutcome(in.Event, guardData{
			Direction:     direction,
			Decision:      decisionFailedClosed,
			FailedClosed:  true,
			FailureReason: reason,
		})
		return nil, closed
	}
	p.warn(ctx, "trustguard could not inspect, failing open", attrs...)
	recordGuardOutcome(in.Event, guardData{
		Direction:     direction,
		Decision:      decisionFailedOpen,
		FailedOpen:    true,
		FailureReason: reason,
	})
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
// when it is. The causes are kept apart because they mean different things to
// whoever reads the trace: there was no body at all, this stage does not handle
// this streaming mode, or the response is being inspected by another leg.
//
// streamGuard says the policy opted into per-block inspection of the response
// (see StreamSettings), so the leg is handed to the stream guard. It is a
// decision from settings, not proof the guard ran; see
// skipReasonInspectedAsStream for the dormant case where it does not. The stage/mode check runs before the empty-body check
// on purpose: a streamed pre_response leg runs when only the headers have
// arrived, so its body is empty by construction, and reading that as
// "empty_response_body" told operators a response the stream guard had
// inspected block by block, and sometimes cut, "had no body" (RUN-1759).
func outputInspectSkipReason(stage policy.Stage, resp *infracontext.ResponseContext, streamGuard bool) string {
	if resp == nil {
		return skipReasonEmptyResponseBody
	}
	switch stage {
	case policy.StagePreResponse:
		if resp.Streaming {
			if streamGuard {
				return skipReasonInspectedAsStream
			}
			return skipReasonStreamingMismatch
		}
	case policy.StagePostResponse:
		if !resp.Streaming {
			return skipReasonStreamingMismatch
		}
		// The body is the truncated one the client got; the stream guard that
		// cut it already reported. Checked before the empty-body test so a cut
		// never reads as "no body".
		if resp.StreamCut {
			return skipReasonStreamCut
		}
	default:
		return skipReasonStreamingMismatch
	}
	if len(resp.Body) == 0 {
		return skipReasonEmptyResponseBody
	}
	return ""
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
