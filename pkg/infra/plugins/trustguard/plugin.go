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
	// skipReasonStreamFinalInspected marks the post_response leg of a stream
	// whose final block the stream guard already evaluated in full under this
	// same policy entry. The drained body is the text that block carried, so a
	// second evaluation only adds a duplicate output row to Activity. A stream
	// whose final block was not evaluated in full (degraded, failed call,
	// accumulation cap, fail-open) keeps this audit: it is then the only
	// full-text pass. Not a coverage gap.
	skipReasonStreamFinalInspected = "stream_final_inspected"
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
	decisionBlocked     = "blocked"
	decisionReported    = "reported"
	decisionAllowed     = "allowed"
	decisionFailedOpen  = "failed_open"
	decisionTransformed = "transformed"
	statusBlock         = "block"
	statusReport        = "report"
	statusTransform     = "transform"
	statusAsk           = "ask"
	statusAllow         = "allow"
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
	// timeout is the deployment-wide deadline (TRUSTGUARD_TIMEOUT) of every
	// evaluate call, and the ceiling of the per-block deadline of a stream.
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
		return p.guardFailure(ctx, in, stageDirection(in.Stage), failureReasonConfigInvalid, err)
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
		return p.guardFailure(ctx, in, direction, failureReasonGatewayIDMissing, nil)
	}

	payload, tgt, halt := p.inspectionPayload(ctx, in, direction, mcpMode)
	if halt != nil {
		return halt.result, halt.err
	}

	if tgt.textBytes > maxBufferedTextBytes {
		return p.guardFailureOmitting(ctx, in, direction, tgt.attachmentsOmitted, failureReasonPayloadTooLarge,
			fmt.Errorf("trustguard: the text exceeds the %d bytes a buffered leg sends", maxBufferedTextBytes))
	}

	// A pod that cannot reach TrustGuard at all — no URL, no credentials: a
	// Secret that did not mount, a partial rollout, a hybrid data plane that
	// received the policy through config sync without the environment — is a
	// failure of the guard, not a finding, so it fails open like any
	// other. Checked only once there is something to inspect, so the failure
	// count is the traffic that actually went through uninspected.
	baseURL := p.baseURL
	if baseURL == "" {
		return p.guardFailureOmitting(ctx, in, direction, tgt.attachmentsOmitted, failureReasonBaseURLMissing, nil)
	}
	if !p.tokens.configured() {
		return p.guardFailureOmitting(ctx, in, direction, tgt.attachmentsOmitted, failureReasonCredentialsMissing, nil)
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
	// call that runs out of time is reported as a timeout rather than as an
	// indistinguishable transport error. The client's own Timeout is only a
	// backstop above this deadline.
	//
	// The first call has the whole budget: a slow answer is still an answer. A
	// request that sends a URL attachment may need a second call without it
	// (below), and that call is made only when its minimum share is left, under
	// the same deadline, never past it.
	deadline := time.Now().Add(p.timeout)
	firstCtx, cancelFirst := context.WithDeadline(ctx, deadline)
	defer cancelFirst()
	resp, err := p.guard(firstCtx, baseURL, cfg.CollectorID, traceID, body, playground)
	if err != nil {
		var rejected *attachmentRejectedError
		if errors.As(err, &rejected) && tgt.urlAttachments > 0 && tgt.withoutURLAttachments != nil {
			// TrustGuard answers "invalid attachment" for every attachment it
			// cannot resolve, a URL it could not fetch included, which is the
			// URL's availability and not this request's content: a CDN that is
			// down must not block legitimate traffic. The text is evaluated again
			// with the URL attachments left out, in a deadline slice of its own,
			// and a verdict that comes back is applied. The call is recorded as a
			// failure that alerts (verdict_incomplete, attachment_not_fetched),
			// because part of what the request carried was never inspected. When
			// less than the minimum share of the budget is left there is no
			// second call, and the request goes through uninspected as the same
			// availability failure. A rejection on the second call comes from an
			// attachment sent as data, which is the content's.
			if !retryHasBudget(time.Now(), deadline, p.timeout) {
				return p.guardFailureOmitting(ctx, in, direction, tgt.attachmentsOmitted, failureReasonVerdictIncomplete,
					fmt.Errorf("trustguard: a URL attachment could not be fetched and too little of the budget is left to evaluate without it"))
			}
			if without, buildErr := tgt.withoutURLAttachments(); buildErr == nil {
				body.Payload = without
				tgt.attachmentsOmitted += tgt.urlAttachments
				tgt.attachmentsNotFetched += tgt.urlAttachments
				tgt.urlAttachments = 0
				retryCtx, cancelRetry := context.WithDeadline(ctx, deadline)
				defer cancelRetry()
				resp, err = p.guard(retryCtx, baseURL, cfg.CollectorID, traceID, body, playground)
			}
		}
	}
	if err != nil {
		var limited *rateLimitedError
		if errors.As(err, &limited) {
			setExtras(in.Event, guardData{Direction: direction, Decision: decisionBlocked, AttachmentsNotInspected: tgt.attachmentsOmitted, AttachmentsNotFetched: tgt.attachmentsNotFetched})
			return nil, rateLimitError(limited)
		}
		return p.guardFailureOmitting(ctx, in, direction, tgt.attachmentsOmitted, reasonOfError(ctx, err), err)
	}

	data := guardData{
		Direction:               direction,
		AttachmentsNotInspected: tgt.attachmentsOmitted,
		AttachmentsNotFetched:   tgt.attachmentsNotFetched,
		Status:                  resp.Status,
		TraceID:                 resp.TraceID,
		RequestID:               resp.RequestID,
		FindingsCount:           len(resp.Findings),
		Findings:                resp.Findings,
	}
	if tgt.attachmentsNotFetched > 0 {
		data.FailureReason = failureReasonVerdictIncomplete
		data.FailureDetail = appplugins.DetailAttachmentNotFetched
		data.FailureClass = string(appplugins.ClassOf(appplugins.FailureVerdictIncomplete, appplugins.DetailAttachmentNotFetched))
		recordEvaluateFailure(ctx, failureReasonVerdictIncomplete)
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
// A 429 is the engine answering, and comes back as a blocking verdict. A
// failure of TrustGuard itself — transport, a timeout, rejected or missing
// credentials, no base URL, unavailable entitlements, a mask that cannot be
// applied — is resolved here: the block is allowed and the failure is published
// on the stream's span at closing. Returning it as an error instead would stop
// the executor from running the rest of the chain on that block, and after a
// few in a row retire inspection for every plugin on the stream, so one broken
// guard would switch off the others.
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

// BoundsStreamPayload declares that the stream executor must hand this plugin a
// block whole (appplugins.StreamPayloadBound). The plugin is one evaluation of
// the whole block, with the position of the block in the stream and the block
// that ends the response as per-call state, and it bounds its own payload, so
// splitting a block that is larger than its window would count the block once
// per piece and send the end of the response several times.
func (p *Plugin) BoundsStreamPayload() bool { return true }

var _ appplugins.StreamPayloadBound = (*Plugin)(nil)

// StreamSettings reports whether these policy settings enable per-block
// inspection of the response leg, and the options the caller must run the
// stream under. Implementing InspectSegment is not the opt-in on its own: this
// plugin is on every pre_response chain that names it, and a policy can opt
// out with streaming.enabled: false or by not selecting the response leg, so
// without this the head gate would be built for policies that turned it off.
//
// head_chars and the rest of the cadence come back with the opt-in because this
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
	if !cfg.Streaming.IsEnabled() || !cfg.selectsStage(policy.StagePreResponse) {
		return false, appplugins.StreamOptions{}
	}
	return true, cfg.Streaming.OptionsWithin(maxStreamWindowBytes)
}

// streamGuardTimeout is how long one streamed block waits for TrustGuard. The
// caller holds the client's bytes for that long, so it is the short stream
// deadline, and the deployment-wide timeout bounds it from above: a deployment
// that tightens TRUSTGUARD_TIMEOUT tightens its streams with it, and a looser
// one never stretches the hold on a client.
func (p *Plugin) streamGuardTimeout() time.Duration {
	if p.timeout > 0 {
		return min(streamingDefaults.GuardTimeout, p.timeout)
	}
	return streamingDefaults.GuardTimeout
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
) (json.RawMessage, transformTarget, *inspectionHalt) {
	if mcpMode {
		return p.mcpInspectionPayload(ctx, in, direction)
	}
	return p.llmInspectionPayload(ctx, in, direction)
}

func (p *Plugin) mcpInspectionPayload(
	ctx context.Context,
	in appplugins.ExecInput,
	direction string,
) (json.RawMessage, transformTarget, *inspectionHalt) {
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
		tgt.textBytes = len(mcpInputText(reqBody))
		payload, err := mcpToolsCallPayload(reqBody)
		if err != nil {
			return nil, tgt, p.payloadFailure(ctx, in, direction, "trustguard mcp tools/call payload build failed", err)
		}
		return payload, tgt, nil
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
	tgt.textBytes = mcpOutputTextBytes(respBody)
	payload, err := mcpToolsResultPayload(respBody)
	if err != nil {
		return nil, tgt, p.payloadFailure(ctx, in, direction, "trustguard mcp tools/result payload build failed", err)
	}
	return payload, tgt, nil
}

func (p *Plugin) llmInspectionPayload(
	ctx context.Context,
	in appplugins.ExecInput,
	direction string,
) (json.RawMessage, transformTarget, *inspectionHalt) {
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
		if decodeErr != nil {
			if adapter.IsRequestDecodeError(decodeErr) && adapter.IsChatRequest(in.Request.ProxyCapability, format) {
				return nil, tgt, p.payloadFailure(ctx, in, direction, "trustguard request body decode failed", decodeErr)
			}
			return p.skipInspection(ctx, in, tgt, direction, skipReasonNoInspectableInput)
		}
		if request != nil && request.DroppedInputItems > 0 {
			p.debug(ctx, "trustguard request input items left out of inspection",
				slog.String("plugin", PluginName),
				slog.Int("dropped_items", request.DroppedInputItems),
			)
		}
		found := extractPayloadAttachments(in.Request.Body)
		attachments, omitted := partitionAttachments(found)
		tgt.attachmentsOmitted = omitted
		tgt.attachmentsNotFetched = countCallerAuthURLs(found)
		tgt.textBytes = requestTextBytes(request)
		tgt.urlAttachments = countURLAttachments(attachments)
		tgt.withoutURLAttachments = func() (json.RawMessage, error) {
			return llmRequestPayloadWithAttachments(request, dataAttachments(attachments))
		}
		if request == nil || (strings.TrimSpace(joinRequestText(request)) == "" && len(attachments) == 0) {
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
			return nil, tgt, p.payloadFailure(ctx, in, direction, "trustguard llm payload build failed", payloadErr)
		}
		return payload, tgt, nil
	}
	if reason := outputInspectSkipReason(in.Stage, in.Response, p.streamGuardOwns(in)); reason != "" {
		return p.skipInspection(ctx, in, tgt, direction, reason)
	}
	response, tools := p.canonicalResponse(in, format)
	if response == nil {
		// canonicalResponse swallows the decode error; without this the gateway
		// cannot tell an undecodable response from an empty one.
		return p.skipInspection(ctx, in, tgt, direction, pluginutil.SkipReasonUndecodableResponse)
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
	tgt.textBytes = responseTextBytes(response, tools)
	payload, payloadErr := llmResponsePayload(response, tools)
	if payloadErr != nil {
		return nil, tgt, p.payloadFailure(ctx, in, direction, "trustguard llm payload build failed", payloadErr)
	}
	return payload, tgt, nil
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
) (json.RawMessage, transformTarget, *inspectionHalt) {
	p.debug(ctx, "trustguard leg not inspected, skipping",
		slog.String("plugin", PluginName),
		slog.String("stage", string(in.Stage)),
		slog.String("direction", direction),
		slog.String("reason", reason),
	)
	setExtras(in.Event, guardData{Direction: direction, Skipped: true, SkipReason: reason, AttachmentsNotInspected: tgt.attachmentsOmitted})
	return nil, tgt, &inspectionHalt{result: passThrough()}
}

// inspectionHalt is what the payload builders return when there is nothing to
// send: the leg was skipped (a pass-through) or its payload could not be built
// and the failure was resolved, which a mode that blocks answers with a refusal.
type inspectionHalt struct {
	result *appplugins.Result
	err    error
}

func (p *Plugin) payloadFailure(ctx context.Context, in appplugins.ExecInput, direction, message string, err error) *inspectionHalt {
	result, refusal := p.guardFailure(ctx, in, direction, failureReasonPayloadUnreadable, fmt.Errorf("%s: %w", message, err))
	return &inspectionHalt{result: result, err: refusal}
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
				return p.transformDegraded(ctx, in, data, resp, reasonTransformNoPayload)
			}
			return p.transformDegraded(ctx, in, data, resp, reasonTransformEncodeFailed)
		}
	}

	masked, ok := transformedInput(resp.TransformedPayload)
	if !ok {
		return p.transformDegraded(ctx, in, data, resp, reasonTransformNoPayload)
	}
	if tgt.apply == nil {
		return p.transformDegraded(ctx, in, data, resp, reasonTransformUnsupported)
	}
	body, ok := tgt.apply(masked)
	if !ok {
		return p.transformDegraded(ctx, in, data, resp, reasonTransformEncodeFailed)
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

// transformDegraded is TrustGuard confirming a finding and asking for it to be
// masked while this plugin cannot write the mask back. Forwarding the original
// would send the data the detector flagged, so a mode that blocks refuses the
// call with the finding's own block, recorded blocked and degraded with the step
// that failed.
func (p *Plugin) transformDegraded(
	ctx context.Context,
	in appplugins.ExecInput,
	data guardData,
	resp *GuardResponse,
	reason string,
) (*appplugins.Result, error) {
	recordEvaluateFailure(ctx, failureReasonTransformFailed)
	data.Degraded = true
	data.DegradedReason = reason
	data.FailureReason = failureReasonTransformFailed
	sharedReason, detail := sharedFailure(failureReasonTransformFailed, reason)
	outcome := appplugins.HandleExternalFailure(appplugins.ExternalFailure{
		Ctx:     ctx,
		Plugin:  PluginName,
		Stage:   in.Stage,
		Mode:    in.Mode,
		Reason:  sharedReason,
		Detail:  detail,
		Finding: blockError(resp, data.Direction),
		Err:     fmt.Errorf("trustguard transform could not be applied: %s", reason),
		Logger:  p.logger,
		Event:   in.Event,
	})
	data.Decision = outcome.Decision
	data.FailureClass = string(outcome.Class)
	data.FailedOpen = outcome.Decision == decisionFailedOpen
	data.FailedClosed = outcome.Decision == decisionFailedClosed
	recordGuardOutcome(in.Event, data)
	if outcome.Err != nil {
		return nil, outcome.Err
	}
	return outcome.Result, nil
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

// guardFailure resolves every failure of the guard itself, as opposed to a
// finding, by the class of its reason (appplugins.ClassOf). One that does not
// depend on the request, which is nearly all of them, lets the request carry on,
// and never silently: the metric counts it and the span carries failed_open with
// the reason, which is what the console reads. One that depends on the request
// itself (a payload this plugin could not read, a body TrustGuard refused for
// its size) is refused in a mode that blocks, as failed_closed, and only
// recorded in observe. A deadline is a failure like any other, so a caller who
// pushes the detector past it gets a payload through uninspected, on the
// record. A deliberate answer (a block, a 429) is not a failure and never comes
// here.
func (p *Plugin) guardFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	direction string,
	reason string,
	err error,
) (*appplugins.Result, error) {
	return p.guardFailureOmitting(ctx, in, direction, 0, reason, err)
}

// guardFailureOmitting is guardFailure for a call that left attachments out of
// the evaluate, so the failure's event still says so.
func (p *Plugin) guardFailureOmitting(
	ctx context.Context,
	in appplugins.ExecInput,
	direction string,
	attachmentsOmitted int,
	reason string,
	err error,
) (*appplugins.Result, error) {
	recordEvaluateFailure(ctx, reason)
	sharedReason, detail := sharedFailure(reason, "")
	outcome := appplugins.HandleExternalFailure(appplugins.ExternalFailure{
		Ctx:    ctx,
		Plugin: PluginName,
		Stage:  in.Stage,
		Mode:   in.Mode,
		Reason: sharedReason,
		Detail: detail,
		Err:    err,
		Logger: p.logger,
		Event:  in.Event,
	})
	failure := guardData{
		Direction:               direction,
		Decision:                outcome.Decision,
		FailedOpen:              outcome.Decision == decisionFailedOpen,
		FailedClosed:            outcome.Decision == decisionFailedClosed,
		FailureReason:           reason,
		FailureClass:            string(outcome.Class),
		AttachmentsNotInspected: attachmentsOmitted,
	}
	if reason == failureReasonVerdictIncomplete {
		failure.FailureDetail = detail
	}
	recordGuardOutcome(in.Event, failure)
	if outcome.Err != nil {
		return nil, outcome.Err
	}
	return outcome.Result, nil
}

// retryMinShare is the share of the evaluation's budget (one part in this many)
// that a second call, without the attachments TrustGuard could not fetch, needs
// to be worth making.
const retryMinShare = 4

// retryHasBudget reports whether the second call has its minimum share of the
// budget left at now.
func retryHasBudget(now, deadline time.Time, budget time.Duration) bool {
	return deadline.Sub(now) >= budget/retryMinShare
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
		if streamGuard && resp.StreamFinalInspected {
			return skipReasonStreamFinalInspected
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
