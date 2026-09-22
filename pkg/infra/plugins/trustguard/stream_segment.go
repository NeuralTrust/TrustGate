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
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const streamIDSeparator = ":"

func (p *Plugin) inspectSegment(
	ctx context.Context,
	in appplugins.ExecInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentVerdict, error) {
	cfg, err := p.config(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("trustguard: %w", err)
	}
	if !cfg.Streaming.Enabled || !cfg.selectsStage(policy.StagePreResponse) {
		return segmentAllow(), nil
	}
	if seg.Closing {
		p.recordStreamOutcome(ctx, in, seg)
		return segmentAllow(), nil
	}
	if p.baseURL == "" || !p.tokens.configured() || p.registry == nil {
		return segmentAllow(), nil
	}
	if in.Request == nil || in.Request.Provider == "" || strings.TrimSpace(in.Request.GatewayID) == "" {
		return segmentAllow(), nil
	}

	payload, ok := p.segmentPayload(ctx, in, seg)
	if !ok {
		return segmentAllow(), nil
	}
	traceID := gatewayTraceID(ctx)
	body := GuardRequest{
		OriginalRequest: requestmeta.FromContext(ctx),
		Payload:         payload,
		Direction:       directionOutput,
		Protocol:        protocolFor(in.Request.ConsumerType),
		GatewayID:       in.Request.GatewayID,
		SessionID:       in.Request.SessionID,
		ConsumerID:      in.Request.ConsumerID,
		Attributes: GuardAttributes{
			ContentType: contentTypeJSON,
			Model: GuardModel{
				Name:     in.Request.RequestedModel,
				Provider: in.Request.Provider,
			},
			User:   principalUser(ctx),
			Stream: segmentStream(traceID, seg),
		},
	}

	// The deadline covers the token leg as well as the evaluate call, which is
	// why the call goes through guardWith and tokenWithin rather than guard: a
	// block that has to wait for a cold token still has to answer inside
	// streaming.guard_timeout, because the caller is holding bytes for it.
	blockCtx, cancel := context.WithTimeout(ctx, cfg.Streaming.guardTimeout())
	defer cancel()
	resp, err := p.guardWith(
		blockCtx,
		p.tokens.tokenWithin,
		p.baseURL,
		cfg.CollectorID,
		traceID,
		body,
		requestHasPlaygroundToken(in.Request),
	)
	if err != nil {
		return p.segmentFailure(ctx, in, seg, err)
	}
	verdict := segmentVerdict(seg, resp)
	fingerprints, unidentified := streamFingerprints(in.Mode, resp.Findings)
	verdict.Fingerprints = fingerprints
	if unidentified > 0 {
		// A stream whose findings all land here reports nothing and reads like
		// a clean one. Synthesising a key for them would fold distinct findings
		// together, so the count is logged rather than published.
		p.debug(ctx, "stream findings carried no identity to fingerprint",
			slog.Int("dropped", unidentified),
			slog.Int("seq", seg.Seq),
			slog.String("slug", in.Config.Slug))
	}
	return verdict, nil
}

// recordStreamOutcome publishes this entry's account of the stream. It runs
// exactly once per stream per entry, on the closing segment, because
// Span.SetExtras overwrites rather than merges: a per-block write would leave
// the span carrying only the last block's account of a response that took
// several.
//
// It also sets the span's latency, which is the one thing about a streamed leg
// the policy chain would otherwise get wrong. A stream span opens on the first
// block and ends when the stream does, so its default wall clock is the whole
// drain — provider generation included — and the fold in pkg/app/metrics counts
// a pre_response span as blocking. Left alone it would charge the provider's
// own time to the policy chain and flatten gateway_ms to zero. The guard
// latency is what the client actually waited for the chain, and it is blocking:
// the block loop runs during stream drain, holding bytes. The executor narrows
// it to this entry's share before the report arrives, so the fold sums the
// chain's spans back to one hold rather than to one per policy.
func (p *Plugin) recordStreamOutcome(
	ctx context.Context,
	in appplugins.ExecInput,
	seg appplugins.StreamSegment,
) {
	if in.Event == nil {
		return
	}
	data := streamOutcome(segmentStreamID(gatewayTraceID(ctx), seg), seg.Report)
	in.Event.SetSLatency(seg.Report.GuardLatency)
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, data.Decision)
	if seg.ReportsStream {
		recordStreamEvals(ctx, seg.Report)
	}
}

// segmentStream places the block in its stream. An id is what the engine
// correlates a stream's calls on, and an empty one is not a missing id but a
// shared one, so without an id the envelope is left off entirely.
func segmentStream(traceID string, seg appplugins.StreamSegment) *GuardStream {
	id := segmentStreamID(traceID, seg)
	if id == "" {
		return nil
	}
	return &GuardStream{
		ID:        id,
		Seq:       seg.Seq,
		Final:     seg.Final,
		Truncated: seg.Truncated,
	}
}

// segmentStreamID derives the wire id from the gateway trace id and the
// response leg. A trace spans one gateway request, so the id is stable for
// every block of the same response and distinct from SessionID, which spans
// the conversation. Without a trace the caller's own correlation handle stands
// in, and when that is empty too the id is empty: an empty id on the wire is
// not a missing id, it is a shared one, and the engine would correlate every
// stream in the process into a single bucket.
func segmentStreamID(traceID string, seg appplugins.StreamSegment) string {
	if traceID != "" {
		return traceID + streamIDSeparator + legResponse
	}
	if strings.TrimSpace(seg.StreamID) == "" {
		return ""
	}
	return seg.StreamID
}

// segmentPayload reuses the framing the buffered response leg gives a whole
// completion, so a partial assistant turn and a complete one differ only in
// how much text they carry.
//
// tools[] is omitted until the final block. indirect_prompt_injection scores
// role=tool content and tools[] descriptions only, and llmResponsePayload
// forwards the request's tools on the output leg, so a tool description that
// trips it would produce one identical finding per block: a cascade in enforce
// mode, and one malicious strike per block in alert-only.
func (p *Plugin) segmentPayload(
	ctx context.Context,
	in appplugins.ExecInput,
	seg appplugins.StreamSegment,
) (json.RawMessage, bool) {
	cresp := &adapter.CanonicalResponse{
		Content:   seg.Accumulated,
		ToolCalls: seg.ToolCalls,
	}
	if strings.TrimSpace(seg.Reasoning) != "" {
		cresp.Reasoning = &adapter.CanonicalReasoning{ThinkingText: seg.Reasoning}
	}
	// Same asymmetry the buffered leg carries: a block whose text is still
	// empty but which already holds a tool call or reasoning text is worth
	// inspecting, and neither of those can be rewritten in place. There
	// llmInspectionPayload leaves transformTarget.apply unset and a transform
	// degrades to a block; segmentVerdict reaches the same answer here.
	if !responseHasInspectableContent(cresp) {
		return nil, false
	}
	var tools []adapter.CanonicalTool
	if seg.Final {
		tools = p.requestTools(in.Request)
	}
	payload, err := llmResponsePayload(cresp, tools)
	if err != nil {
		// The block goes uninspected, exactly as the buffered leg's own
		// payload failure does, so it belongs in the same counter. transport
		// is the closest of the two reasons the counter knows; the per-block
		// breakdown arrives with the stream aggregate.
		recordEvaluateFailure(ctx, failureReasonTransport)
		p.warn(ctx, "trustguard stream segment payload build failed, skipping block",
			slog.String("plugin", PluginName),
			slog.Int("seq", seg.Seq),
			slog.Any("error", err),
		)
		return nil, false
	}
	return payload, true
}

func (p *Plugin) requestTools(req *infracontext.RequestContext) []adapter.CanonicalTool {
	if req == nil {
		return nil
	}
	format, err := adapter.ResolveAgentFormat(req.Provider, req.SourceFormat, nil)
	if err != nil {
		return nil
	}
	request, err := p.registry.DecodeRequestFor(req.Body, format)
	if err != nil || request == nil {
		return nil
	}
	return request.Tools
}

// segmentFailure splits the guard's failures into the ones the caller may
// weigh against streaming.on_error and the ones it may not. A rejection the
// engine issued deliberately — 401/403, 429, 503 — comes back as a blocking
// verdict, which no configuration can relax, matching what Execute does on the
// buffered path. Everything else is returned as an error for the caller to
// resolve.
func (p *Plugin) segmentFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	seg appplugins.StreamSegment,
	err error,
) (*appplugins.SegmentVerdict, error) {
	var limited *rateLimitedError
	if errors.As(err, &limited) {
		return segmentBlock(typeRateLimited, rateLimitMessage), nil
	}
	var unavailable *entitlementsUnavailableError
	if errors.As(err, &unavailable) {
		return segmentBlock(typeUnavailable, unavailableMessage), nil
	}
	var auth *authRejectedError
	if errors.As(err, &auth) || errors.Is(err, errUnauthorized) {
		recordEvaluateFailure(ctx, failureReasonUnauthorized)
		p.error(ctx, "trustguard stream auth/config rejected, failing closed",
			slog.String("plugin", PluginName),
			slog.String("direction", directionOutput),
			slog.Int("seq", seg.Seq),
			slog.Any("error", err),
		)
		return segmentBlock(typeUnauthorized, unauthorizedMessage), nil
	}
	recordEvaluateFailure(ctx, failureReasonTransport)
	p.warn(ctx, "trustguard stream segment call failed",
		slog.String("plugin", PluginName),
		slog.String("stage", string(in.Stage)),
		slog.Int("seq", seg.Seq),
		slog.Any("error", err),
	)
	return nil, fmt.Errorf("trustguard: inspecting stream segment %d: %w", seg.Seq, err)
}

func segmentVerdict(seg appplugins.StreamSegment, resp *GuardResponse) *appplugins.SegmentVerdict {
	switch resp.Status {
	case statusTransform:
		// A transform replaces the whole accumulated buffer. With nothing
		// accumulated the flagged content is a tool call or reasoning text,
		// which the buffer does not carry: applying the mask would neither
		// remove the flagged bytes nor leave them where they were, it would
		// inject assistant text where a tool call or a thought stood. Execute
		// refuses the same response through reasonTransformUnsupported.
		if strings.TrimSpace(seg.Accumulated) == "" {
			return segmentBlock(typeBlocked, clientBlockMessage(resp))
		}
		masked, ok := transformedInput(resp.TransformedPayload)
		if !ok {
			return segmentBlock(typeBlocked, clientBlockMessage(resp))
		}
		return &appplugins.SegmentVerdict{HasTransform: true, Transformed: masked}
	case statusBlock, statusAsk:
		return segmentBlock(typeBlocked, clientBlockMessage(resp))
	default:
		return segmentAllow()
	}
}

func segmentAllow() *appplugins.SegmentVerdict {
	return &appplugins.SegmentVerdict{}
}

func segmentBlock(kind, message string) *appplugins.SegmentVerdict {
	return &appplugins.SegmentVerdict{Block: true, Type: kind, Message: message}
}
