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
	"sync"
	"time"

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
		// Another policy on the route can have streaming on, and then this
		// entry is asked about every block. An error would stop the executor
		// from running the rest of the chain, so settings that do not parse
		// fail open here as they do in Execute.
		if !seg.Closing {
			recordEvaluateFailure(ctx, failureReasonConfigInvalid)
		}
		return segmentAllow(), nil
	}
	if !cfg.Streaming.enabled() || !cfg.selectsStage(policy.StagePreResponse) {
		return segmentAllow(), nil
	}
	if seg.Closing {
		p.recordStreamOutcome(ctx, in, seg)
		return segmentAllow(), nil
	}
	if p.registry == nil {
		return segmentAllow(), nil
	}
	if p.streamRetired(ctx, in, seg) {
		return segmentAllow(), nil
	}
	if in.Request == nil || in.Request.Provider == "" || strings.TrimSpace(in.Request.GatewayID) == "" {
		return segmentAllow(), nil
	}

	payload, ok := p.segmentPayload(ctx, in, seg)
	if !ok {
		return segmentAllow(), nil
	}
	if p.baseURL == "" {
		return p.segmentGuardFailure(ctx, in, cfg, seg, failureReasonBaseURLMissing, errors.New("trustguard: base url not configured"))
	}
	if !p.tokens.configured() {
		return p.segmentGuardFailure(ctx, in, cfg, seg, failureReasonCredentialsMissing, errors.New("trustguard: client credentials not configured"))
	}
	traceID := gatewayTraceID(ctx)
	// Counted here, after every check that can skip the call, so the position is
	// that of an evaluate that is really sent. A block that fails on the wire was
	// still sent and keeps its place.
	block := p.nextStreamBlock(ctx, in, seg)
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
			Stream: segmentStream(traceID, seg, block),
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
		return p.segmentFailure(ctx, in, cfg, seg, err)
	}
	p.streamRecovered(ctx, in, seg)
	verdict, err := segmentVerdict(seg, resp)
	if err != nil {
		return p.segmentGuardFailure(ctx, in, cfg, seg, failureReasonTransformFailed, err)
	}
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
	// Taken out before anything can return, so a stream with no event does
	// not leave its entry behind.
	var failure *streamFailure
	if key, ok := streamFailureKey(ctx, in, seg); ok {
		if v, loaded := p.streamFailures.LoadAndDelete(key); loaded {
			failure, _ = v.(*streamFailure)
		}
	}
	p.forgetStreamPosition(ctx, in, seg)
	if in.Event == nil {
		return
	}
	data := streamOutcome(segmentStreamID(gatewayTraceID(ctx), seg), seg.Report)
	// A stream that was cut reports blocked even if earlier blocks failed
	// open; those still count in trustguard_evaluate_failures_total.
	failedOpen := failure != nil && data.Decision != decisionBlocked
	if failedOpen {
		data.Decision = decisionFailedOpen
		data.FailedOpen = true
		data.FailureReason = failure.reason
		if failure.retired() && data.Streaming != nil && data.Streaming.FallbackReason == "" {
			data.Streaming.FallbackReason = fallbackReasonSegmentationUnavail
		}
	}
	if prints := findingPrints(seg.Findings); len(prints) > 0 {
		data.FindingsCount = len(prints)
		data.Streaming.Findings = prints
	}
	in.Event.SetSLatency(seg.Report.GuardLatency)
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, data.Decision)
	if seg.ReportsStream {
		recordStreamEvals(ctx, seg.Report, failedOpen)
	}
}

// findingPrints is the set the event carries, without the entry the executor
// already narrowed it by. The entry a fingerprint belongs to is the span it is
// written on.
func findingPrints(findings []appplugins.StreamFinding) []string {
	prints := make([]string, 0, len(findings))
	for _, finding := range findings {
		prints = append(prints, finding.Fingerprint)
	}
	return prints
}

// segmentStream places the block in its stream. An id is what the engine
// correlates a stream's calls on, and an empty one is not a missing id but a
// shared one, so without an id the envelope is left off entirely.
func segmentStream(traceID string, seg appplugins.StreamSegment, block int) *GuardStream {
	id := segmentStreamID(traceID, seg)
	if id == "" {
		return nil
	}
	return &GuardStream{
		ID:        id,
		Seq:       seg.Seq,
		Block:     block,
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

// segmentFailure splits the guard's failures from its answers. A 429 is the
// engine refusing deliberately and comes back as a blocking verdict, matching
// what Execute does on the buffered path. Everything else — transport, 5xx,
// a block that ran out of time, rejected credentials, unavailable entitlements
// — is a failure of the guard and is resolved by segmentGuardFailure.
func (p *Plugin) segmentFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	seg appplugins.StreamSegment,
	err error,
) (*appplugins.SegmentVerdict, error) {
	var limited *rateLimitedError
	if errors.As(err, &limited) {
		return segmentBlock(typeRateLimited, rateLimitMessage), nil
	}
	reason := failureReasonTransport
	var unavailable *entitlementsUnavailableError
	var auth *authRejectedError
	switch {
	case errors.As(err, &unavailable):
		reason = failureReasonEntitlementsUnavailable
	case errors.As(err, &auth), errors.Is(err, errUnauthorized):
		reason = failureReasonUnauthorized
	case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
		reason = failureReasonTimeout
	}
	return p.segmentGuardFailure(ctx, in, cfg, seg, reason, err)
}

// segmentGuardFailure is guardFailure for one streamed block. Under the
// default streaming.on_error (fail_open) it allows the block and remembers why,
// so the closing segment publishes failed_open and the reason on the stream's
// span; the rest of the chain keeps inspecting the block and the stream guard
// never retires on our account. Under fail_closed the failure goes back as an
// error for the caller to cut on.
func (p *Plugin) segmentGuardFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	seg appplugins.StreamSegment,
	reason string,
	err error,
) (*appplugins.SegmentVerdict, error) {
	recordEvaluateFailure(ctx, reason)
	attrs := []any{
		slog.String("plugin", PluginName),
		slog.String("direction", directionOutput),
		slog.Int("seq", seg.Seq),
		slog.String("reason", reason),
		slog.Any("error", err),
	}
	if cfg.Streaming.OnError == onErrorFailClosed {
		p.error(ctx, "trustguard could not inspect stream segment, failing closed", attrs...)
		return nil, fmt.Errorf("trustguard: inspecting stream segment %d: %w", seg.Seq, err)
	}
	p.warn(ctx, "trustguard could not inspect stream segment, failing open", attrs...)
	p.streamFailed(ctx, in, seg, reason)
	return segmentAllow(), nil
}

// streamFailure is one stream's record, for one policy, of a guard that could
// not inspect it.
type streamFailure struct {
	reason      string
	consecutive int
	at          time.Time
}

const (
	// streamRetireAfter failed blocks in a row stop this policy calling the
	// guard for the rest of the stream, as the stream guard does for failures
	// it sees. Failing open hides them from it, and without this a guard that
	// hangs would hold every block of every stream for guard_timeout.
	streamRetireAfter = 3
	// streamFailureTTL bounds an entry whose closing segment never came.
	streamFailureTTL = 10 * time.Minute
)

func (f *streamFailure) retired() bool { return f.consecutive >= streamRetireAfter }

// streamFailureKey names one stream for one policy. Without a stream identity
// (no trace, which is the case with telemetry off) there is no key: every
// stream on the pod would share one, and one stream's failures would retire
// inspection for all the others. Such a stream fails open block by block and
// keeps no record.
func streamFailureKey(ctx context.Context, in appplugins.ExecInput, seg appplugins.StreamSegment) (string, bool) {
	id := segmentStreamID(gatewayTraceID(ctx), seg)
	if id == "" {
		return "", false
	}
	return id + "\x00" + in.Config.ID, true
}

func (p *Plugin) streamRetired(ctx context.Context, in appplugins.ExecInput, seg appplugins.StreamSegment) bool {
	key, ok := streamFailureKey(ctx, in, seg)
	if !ok {
		return false
	}
	v, ok := p.streamFailures.Load(key)
	if !ok {
		return false
	}
	f, _ := v.(*streamFailure)
	if f == nil || !f.retired() {
		return false
	}
	// A retired entry is never written again by streamFailed, so the sweep
	// would otherwise take it from a stream that is still running.
	p.streamFailures.Store(key, &streamFailure{reason: f.reason, consecutive: f.consecutive, at: time.Now()})
	return true
}

// streamFailed and streamRecovered run for one stream's blocks, which the
// stream guard evaluates one at a time, so each entry has a single writer.
func (p *Plugin) streamFailed(ctx context.Context, in appplugins.ExecInput, seg appplugins.StreamSegment, reason string) {
	key, ok := streamFailureKey(ctx, in, seg)
	if !ok {
		return
	}
	f := &streamFailure{reason: reason, consecutive: 1, at: time.Now()}
	if v, ok := p.streamFailures.Load(key); ok {
		if prev, _ := v.(*streamFailure); prev != nil {
			f.consecutive = prev.consecutive + 1
		}
	}
	p.streamFailures.Store(key, f)
	p.sweepStreamFailures(f.at)
}

// streamRecovered resets the run of failures after a block the guard did
// answer, and keeps the reason: earlier blocks still went through uninspected.
func (p *Plugin) streamRecovered(ctx context.Context, in appplugins.ExecInput, seg appplugins.StreamSegment) {
	key, ok := streamFailureKey(ctx, in, seg)
	if !ok {
		return
	}
	v, ok := p.streamFailures.Load(key)
	if !ok {
		return
	}
	if prev, _ := v.(*streamFailure); prev != nil {
		p.streamFailures.Store(key, &streamFailure{reason: prev.reason, at: time.Now()})
	}
}

// sweepStreamFailures drops entries older than streamFailureTTL, at most once
// a minute, so a stream whose closing never arrived cannot grow the map.
func (p *Plugin) sweepStreamFailures(now time.Time) {
	last := p.streamSweptAt.Load()
	if now.UnixNano()-last < int64(time.Minute) || !p.streamSweptAt.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	p.streamFailures.Range(func(k, v any) bool {
		if f, _ := v.(*streamFailure); f == nil || now.Sub(f.at) > streamFailureTTL {
			p.streamFailures.Delete(k)
		}
		return true
	})
}

// streamPosition is how many evaluates one policy has sent for one stream.
type streamPosition struct {
	mu   sync.Mutex
	sent int
	at   time.Time
}

// nextStreamBlock returns the 1-based position of the evaluate about to be sent
// for this stream, or 0 when the stream has no identity to count under (no
// trace and no caller handle). That is the same condition under which the
// stream envelope is dropped altogether, so a 0 never reaches the wire: without
// an id there is nothing to correlate the calls on.
func (p *Plugin) nextStreamBlock(ctx context.Context, in appplugins.ExecInput, seg appplugins.StreamSegment) int {
	key, ok := streamFailureKey(ctx, in, seg)
	if !ok {
		return 0
	}
	v, _ := p.streamBlocks.LoadOrStore(key, &streamPosition{})
	pos, _ := v.(*streamPosition)
	if pos == nil {
		return 0
	}
	now := time.Now()
	pos.mu.Lock()
	pos.sent++
	pos.at = now
	n := pos.sent
	pos.mu.Unlock()
	p.sweepStreamBlocks(now)
	return n
}

// forgetStreamPosition drops the stream's counter when its closing segment
// arrives, so a finished stream leaves nothing behind.
func (p *Plugin) forgetStreamPosition(ctx context.Context, in appplugins.ExecInput, seg appplugins.StreamSegment) {
	if key, ok := streamFailureKey(ctx, in, seg); ok {
		p.streamBlocks.Delete(key)
	}
}

// sweepStreamBlocks drops counters untouched for longer than streamFailureTTL,
// at most once a minute, so a stream whose closing never arrived cannot grow the
// map.
func (p *Plugin) sweepStreamBlocks(now time.Time) {
	last := p.streamBlocksSweptAt.Load()
	if now.UnixNano()-last < int64(time.Minute) || !p.streamBlocksSweptAt.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	p.streamBlocks.Range(func(k, v any) bool {
		pos, _ := v.(*streamPosition)
		if pos == nil {
			p.streamBlocks.Delete(k)
			return true
		}
		pos.mu.Lock()
		stale := now.Sub(pos.at) > streamFailureTTL
		pos.mu.Unlock()
		if stale {
			p.streamBlocks.Delete(k)
		}
		return true
	})
}

// errTransformUnappliable is a transform this plugin cannot write into the
// stream. It is a failure on our side, not a finding, and is resolved like any
// other: by default the text goes on unmasked.
var errTransformUnappliable = errors.New("trustguard: stream transform cannot be applied")

func segmentVerdict(seg appplugins.StreamSegment, resp *GuardResponse) (*appplugins.SegmentVerdict, error) {
	switch resp.Status {
	case statusTransform:
		// A transform replaces the whole accumulated buffer. With nothing
		// accumulated the flagged content is a tool call or reasoning text,
		// which the buffer does not carry: applying the mask would neither
		// remove the flagged bytes nor leave them where they were, it would
		// inject assistant text where a tool call or a thought stood. Execute
		// treats the same response through reasonTransformUnsupported.
		if strings.TrimSpace(seg.Accumulated) == "" {
			return nil, errTransformUnappliable
		}
		masked, ok := transformedInput(resp.TransformedPayload)
		if !ok {
			return nil, errTransformUnappliable
		}
		return &appplugins.SegmentVerdict{HasTransform: true, Transformed: masked}, nil
	case statusBlock, statusAsk:
		return segmentBlock(typeBlocked, clientBlockMessage(resp)), nil
	default:
		return segmentAllow(), nil
	}
}

func segmentAllow() *appplugins.SegmentVerdict {
	return &appplugins.SegmentVerdict{}
}

func segmentBlock(kind, message string) *appplugins.SegmentVerdict {
	return &appplugins.SegmentVerdict{Block: true, Type: kind, Message: message}
}
