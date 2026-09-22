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

package proxy

import (
	"cmp"
	"context"
	"iter"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

// segmentRunner is the executor's per-segment leg. It is declared here, at its
// only consumer, so RunStreamSegment stays off the exported Executor interface
// and out of the generated mocks every other caller shares.
type segmentRunner interface {
	RunStreamSegment(
		ctx context.Context,
		in appplugins.StageInput,
		seg appplugins.StreamSegment,
	) (*appplugins.SegmentOutcome, error)
}

// streamOnError is what the guard does with held text when a guard call fails
// for a reason the operator can configure away.
type streamOnError string

const (
	streamFailOpen   streamOnError = "fail_open"
	streamFailClosed streamOnError = "fail_closed"
)

const (
	defaultHeadChars          = 400
	streamBlockMessage        = "Response blocked by guardrail policy."
	streamUnverifiableMessage = "Response blocked: guardrail inspection unavailable."
	// streamUnverifiableType separates "we could not verify this" from
	// "the guard rejected it" on the wire, which are different incidents for
	// a client deciding whether to retry.
	streamUnverifiableType = "guardrail_unverifiable"

	streamMaskedMessage = "Response blocked: guardrail masking is not available on a streamed response."
	// streamMaskedType marks a block the policy did not ask for: the guard
	// returned a mask, which the head gate cannot apply yet, so it escalated.
	// A client seeing this is being denied something a buffered call would
	// have received with the sensitive span masked.
	streamMaskedType = "guardrail_masked_unsupported"
)

// maxHeadHeldBytes bounds what the head gate holds. head_chars does not: an
// event the codec cannot decode contributes no inspectable text, so on an
// undecodable stream chars never advances and the head would run to the
// terminal event — de-streaming the whole response onto the live request path.
// A provider line may be 2 MiB (infra/providers/stream.go), so the ceiling is
// tested before each pull and may be exceeded by at most one line.
//
// The block loop reuses it as the ceiling on what one block may hold, for the
// same reason: a stream whose events carry no inspectable text closes no block
// on chars and none on the clock either once the gate's ceiling is measured
// against an idle guard, so without it the rest of the response accumulates.
const maxHeadHeldBytes = 256 << 10

const (
	defaultMinCharsBetweenEvals = 2048
	defaultMaxHold              = 800 * time.Millisecond
	defaultMaxAccumulatedBytes  = 256 << 10
	// maxAccumulatedCeiling bounds what any configuration can put in front of
	// the engine. detectAll returns nil above 1 MiB and says nothing, so a
	// payload that crosses it is not inspected at all and looks clean.
	maxAccumulatedCeiling = 1 << 20
	// maxConsecutiveFailures is how many failing calls in a row retire the
	// block loop. Past that they are latency spent on held text for a verdict
	// that is not arriving, and the buffered post_response pass still audits
	// the whole response.
	maxConsecutiveFailures = 3
)

// Why a stream stopped being inspected the way the policy asked. A degrade is
// per block and recoverable; a fallback retires the block loop for the rest of
// the stream. Telemetry publishes them in a later slice — they are recorded
// here so that no degradation is silent.
const (
	degradeAccumulationCap      = "accumulation_cap"
	degradeGuardTimeout         = "guard_timeout"
	fallbackSegmentationUnavail = "segmentation_unavailable"
	fallbackClientDisconnected  = "client_disconnected"
)

type streamGuardConfig struct {
	headChars     int
	onError       streamOnError
	minChars      int
	maxHold       time.Duration
	maxAccumBytes int
}

func (c streamGuardConfig) withDefaults() streamGuardConfig {
	if c.headChars <= 0 {
		c.headChars = defaultHeadChars
	}
	if c.onError != streamFailClosed {
		c.onError = streamFailOpen
	}
	if c.minChars <= 0 {
		c.minChars = defaultMinCharsBetweenEvals
	}
	if c.maxHold <= 0 {
		c.maxHold = defaultMaxHold
	}
	if c.maxAccumBytes <= 0 {
		c.maxAccumBytes = defaultMaxAccumulatedBytes
	}
	if c.maxAccumBytes > maxAccumulatedCeiling {
		c.maxAccumBytes = maxAccumulatedCeiling
	}
	return c
}

// streamGuard holds the head of a streaming response until a verdict covers
// it. produced is every event pulled from the source in arrival order;
// releasedIdx counts the events already handed to the client and clearedIdx
// the events a clean verdict covers, so releasedIdx <= clearedIdx <=
// len(produced) holds after every step.
//
// Past the head the same three counters drive the block loop: gate closes the
// block being filled, seq numbers the call it is owed, and sentChars marks how
// much of the produced text earlier calls already carried as their own delta.
type streamGuard struct {
	runner segmentRunner
	seg    *segmenter
	in     appplugins.StageInput
	cfg    streamGuardConfig
	source adapter.Format
	logger *slog.Logger
	now    func() time.Time

	next func() ([]byte, error, bool)
	stop func()

	streamID    string
	produced    []*streamEvent
	releasedIdx int
	clearedIdx  int
	chars       int
	held        int
	text        strings.Builder
	reasoning   strings.Builder
	tools       toolCallDigest
	terminal    bool
	exhausted   bool
	srcErr      error

	gate           *blockGate
	seq            int
	sentChars      int
	finalSent      bool
	failures       int
	silenced       bool
	stopped        bool
	degradedReason string
	fallbackReason string
}

func newStreamGuard(
	runner segmentRunner,
	codec streamCodec,
	source adapter.Format,
	in appplugins.StageInput,
	cfg streamGuardConfig,
	logger *slog.Logger,
) *streamGuard {
	return &streamGuard{
		runner: runner,
		seg:    newSegmenter(codec, source),
		in:     in,
		cfg:    cfg.withDefaults(),
		source: source,
		logger: logger,
		now:    time.Now,
	}
}

// Run evaluates the head of the stream before a single byte reaches the client,
// which is the only point at which a violation can still be a real HTTP status:
// finalizeStream has not returned, so status and headers are unset.
//
// It returns the sequence the caller must consume. After a clean verdict that
// is the cleared head replayed byte for byte, followed by the block loop over
// the rest of the source. On a head-gate block it is only the undrained
// remainder, which the caller drains and discards: the source has already been
// pulled from and cannot be ranged a second time.
//
// Run owns the pull coroutine only until it hands it to the sequence it
// returns, which stops it on a defer. Until that handover a panic would park
// the coroutine with the upstream body unclosed, so the handover is guarded
// here too. iter.Pull2's stop is idempotent, so the two paths cannot conflict.
func (g *streamGuard) Run(
	ctx context.Context,
	src iter.Seq2[[]byte, error],
) (iter.Seq2[[]byte, error], *appplugins.PluginError) {
	spanCtx, release := appplugins.NewStreamSpanContext(ctx)
	g.streamID = streamCorrelationID(ctx)
	g.next, g.stop = iter.Pull2(src)
	handed := false
	defer func() {
		if !handed {
			g.stop()
			release()
		}
	}()
	if pe := g.head(spanCtx); pe != nil {
		release()
		handed = true
		return g.remainder(), pe
	}
	handed = true
	return g.replay(spanCtx, release), nil
}

func streamCorrelationID(ctx context.Context) string {
	rt := trace.FromContext(ctx)
	if rt == nil {
		return ""
	}
	return rt.TraceID()
}

// head drains the source until the head block closes and evaluates it. The
// block closes on head_chars of inspectable text, on maxHeadHeldBytes of held
// wire bytes, on the terminal event or on the end of the source. There is no
// time ceiling: it would hand the guard less than head_chars of text and still
// commit the status, which is the one decision this gate exists to make well.
//
// The byte ceiling can fall mid-event, so the segmenter is flushed there as it
// is at the end of the source: lines already pulled but not yet framed live in
// the segmenter, and the remainder yields only what comes after them.
func (g *streamGuard) head(ctx context.Context) *appplugins.PluginError {
	for g.chars < g.cfg.headChars && g.held < maxHeadHeldBytes {
		line, err, ok := g.next()
		if !ok {
			g.exhausted = true
			break
		}
		if err != nil {
			g.srcErr = err
			break
		}
		g.held += len(line)
		if g.admit(g.seg.feed(line)) {
			break
		}
	}
	if g.exhausted || g.srcErr != nil || g.held >= maxHeadHeldBytes {
		g.admit(g.seg.flush())
	}
	return g.evaluate(ctx)
}

// admit records a completed event and reports whether it closes the unit being
// filled: the head block while the gate is still nil, and the block the gate
// owns once the loop has taken over. A classification failure arrives
// alongside its event and never instead of it, so returning early on the error
// would drop wire bytes the client is owed.
func (g *streamGuard) admit(ev *streamEvent, err error) bool {
	if err != nil && g.logger != nil {
		g.logger.Warn("stream event classification failed; releasing it uninspected",
			slog.String("format", string(g.source)),
			slog.String("error", err.Error()))
	}
	if ev == nil {
		return false
	}
	g.produced = append(g.produced, ev)
	g.chars += ev.chars()
	g.text.WriteString(ev.text)
	g.reasoning.WriteString(ev.reasoning)
	g.tools.merge(ev.toolCalls)
	// The prelude fast-path: an opaque event that opens a block carries no
	// inspectable text, so counting it as cleared lets evaluate skip the guard
	// call entirely when the whole head is opaque. It is not an early release —
	// nothing reaches the client before replay, which runs strictly after the
	// verdict. Once the block carries anything else the event rides with it, or
	// the wire order changes.
	if ev.unit == unitOpaque && g.clearedIdx == len(g.produced)-1 {
		g.clearedIdx = len(g.produced)
	}
	if ev.unit == unitTerminal {
		g.terminal = true
	}
	if g.gate == nil {
		return ev.unit == unitTerminal
	}
	g.gate.admit(ev)
	return g.gate.shouldClose(ev)
}

func (g *streamGuard) evaluate(ctx context.Context) *appplugins.PluginError {
	if g.clearedIdx == len(g.produced) {
		return nil
	}
	outcome, err := g.runner.RunStreamSegment(ctx, g.in, g.nextSegment())
	if err != nil {
		return g.headFailure(err)
	}
	if outcome != nil && outcome.Block {
		return blockedHeadError(g.source, outcome)
	}
	// A transform escalates to a block until the buffer rewrite lands. Releasing
	// the head unmasked would turn a masking policy into a no-op on every
	// streamed response, and at the head nothing is committed yet, so escalating
	// costs a status code rather than a truncated body.
	if outcome != nil && outcome.HasTransform {
		return streamError(g.source, streamMaskedType, streamMaskedMessage)
	}
	g.clearedIdx = len(g.produced)
	return nil
}

// headFailure resolves streaming.on_error. The plugin hands a configurable
// failure back as an error precisely so that it is resolved here: only the
// guard knows that at the head nothing is committed, which is what makes
// fail_closed a clean status code instead of a truncated body.
func (g *streamGuard) headFailure(err error) *appplugins.PluginError {
	g.failures++
	if g.logger != nil {
		g.logger.Warn("stream head inspection failed",
			slog.String("on_error", string(g.cfg.onError)),
			slog.String("error", err.Error()))
	}
	if g.cfg.onError == streamFailClosed {
		return streamError(g.source, streamUnverifiableType, streamUnverifiableMessage)
	}
	g.clearedIdx = len(g.produced)
	return nil
}

func blockedHeadError(source adapter.Format, outcome *appplugins.SegmentOutcome) *appplugins.PluginError {
	message := outcome.Message
	if message == "" {
		message = streamBlockMessage
	}
	return streamError(source, outcome.Type, message)
}

func streamError(source adapter.Format, errType, message string) *appplugins.PluginError {
	pe := &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Type:       errType,
		Message:    message,
	}
	if adapter.NeedsAdaptedError(source) {
		pe.Body = adapter.EncodeErrorBody(source, pe.StatusCode, message)
	}
	return pe
}

// replay writes the events the head verdict cleared and then runs the block
// loop over the rest of the source. Nothing is re-encoded: a re-encode would
// reorder usage, provider extensions and comments on a wire that is byte-exact
// by contract.
//
// The per-stream context is owned here and cancelled on the way out, which is
// the only disconnect signal there is: c.UserContext() is not cancelled when a
// client leaves and fasthttp's RequestCtx.Done() fires only on shutdown, so
// propagation is pull-based. A client that leaves during a call is therefore
// noticed when yield next reports false, not while the call is in flight.
func (g *streamGuard) replay(ctx context.Context, release func()) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		streamCtx, cancel := context.WithCancel(ctx)
		defer release()
		defer g.stop()
		defer cancel()
		if !g.flush(yield) {
			return
		}
		g.blockLoop(streamCtx, yield)
	}
}

// blockLoop fills one block at a time, inspects it and writes what the verdict
// clears. The call is issued inline, on the goroutine that drives the stream,
// so exactly one call is ever in flight: that is the shape of the loop, not a
// counter it keeps or a setting it reads, and it is what makes every payload a
// contiguous prefix of the text produced so far.
func (g *streamGuard) blockLoop(ctx context.Context, yield func([]byte, error) bool) {
	g.gate = newBlockGate(g, g.cfg.minChars, g.cfg.maxHold)
	for !g.stopped {
		line, err, ok := g.next()
		if !ok {
			g.exhausted = true
			break
		}
		if err != nil {
			g.srcErr = err
			break
		}
		g.held += len(line)
		if !g.admit(g.seg.feed(line)) && g.held < maxHeadHeldBytes {
			continue
		}
		g.inspect(ctx)
		g.gate.reset()
		if !g.flush(yield) {
			return
		}
	}
	if g.stopped {
		return
	}
	g.admit(g.seg.flush())
	g.inspect(ctx)
	if !g.flush(yield) {
		return
	}
	if g.srcErr != nil {
		yield(nil, g.srcErr)
	}
}

// inspect issues the one call the closed block is owed and resolves the
// verdict. Everything it can do to a late or failing verdict is a degrade: it
// releases text rather than truncating a response the client is already
// reading. A verdict that says block is the one thing it cannot degrade, so it
// stops the stream where it stands; the honest per-format terminator for that
// stop is the next slice.
func (g *streamGuard) inspect(ctx context.Context) {
	if g.clearedIdx == len(g.produced) {
		return
	}
	// Finality is latched, not derived: unitTerminal is not unique per stream,
	// OpenAI emitting the finish-reason chunk and then data: [DONE], Anthropic
	// message_stop after message_delta. Once the final block has been
	// inspected every later terminal event is released without a new call.
	if g.silenced || g.finalSent {
		g.clearedIdx = len(g.produced)
		return
	}
	if ctx.Err() != nil {
		g.retire(fallbackClientDisconnected)
		return
	}
	outcome, err := g.runner.RunStreamSegment(ctx, g.in, g.nextSegment())
	if err != nil {
		g.blockFailure(err)
		return
	}
	g.failures = 0
	// A transform escalates to a block for the same reason it does at the
	// head: releasing the text unmasked would turn a masking policy into a
	// no-op on every streamed response.
	if outcome != nil && (outcome.Block || outcome.HasTransform) {
		g.stopStream(outcome)
		return
	}
	g.clearedIdx = len(g.produced)
}

// nextSegment builds the envelope for the call this block is owed. It advances
// the sequence, the block delta and the finality latch, so it runs exactly
// once per call and only when a call is actually issued.
//
// Accumulated is built from the text the provider produced, never from the
// text already released: a finding split across the block in flight and the
// block being inspected would otherwise be read by no call at all.
func (g *streamGuard) nextSegment() appplugins.StreamSegment {
	produced := g.text.String()
	accumulated, reasoning, calls, capped := g.budget(produced, g.reasoning.String(), g.tools.calls())
	if capped {
		g.degrade(degradeAccumulationCap)
	}
	final := g.final() && !g.finalSent
	g.finalSent = g.finalSent || final
	g.seq++
	text := produced[g.sentChars:]
	g.sentChars = len(produced)
	return appplugins.StreamSegment{
		StreamID:    g.streamID,
		Seq:         g.seq,
		Final:       final,
		Truncated:   capped,
		Text:        text,
		Accumulated: accumulated,
		Reasoning:   reasoning,
		ToolCalls:   calls,
	}
}

func (g *streamGuard) final() bool {
	return g.terminal || g.exhausted || g.srcErr != nil
}

// budget spends max_accumulated_bytes across everything one call carries, as a
// sum. The engine reads the three fields as a single CanonicalResponse —
// segmentPayload puts text, reasoning and every tool call into one of them
// (trustguard/stream_segment.go) — and detectAll returns nil above 1 MiB
// without saying so. Capping each field on its own, and tool calls not at all,
// therefore bounds nothing: at the configuration ceiling a reasoning model
// sends 2 MiB, and at the 256 KiB default an agentic stream crosses 1 MiB on
// tool-call arguments alone. Both are valid configurations, and both land in
// the silence B7.4 exists to keep the guard out of.
//
// The split is max-min fair: a field shorter than its equal share is carried
// whole and the slack widens the share of the fields still short, so a one-line
// answer beside a long reasoning trace is never dropped to make room for it and
// no field can starve another. What a field cannot fit is its oldest bytes —
// each grant is that field's tail, last in wins — advanced to the next rune
// boundary so the engine never reads a payload that opens mid-character.
//
// calls is the digest's own copy, so windowing arguments in place does not
// shorten what the next block accumulates.
func (g *streamGuard) budget(
	text, reasoning string,
	calls []adapter.CanonicalToolCall,
) (string, string, []adapter.CanonicalToolCall, bool) {
	carried := len(text) + len(reasoning)
	for _, call := range calls {
		carried += len(call.Arguments)
	}
	if carried <= g.cfg.maxAccumBytes {
		return text, reasoning, calls, false
	}
	sizes := make([]int, 0, len(calls)+2)
	sizes = append(sizes, len(text), len(reasoning))
	for _, call := range calls {
		sizes = append(sizes, len(call.Arguments))
	}
	grants := shareBudget(g.cfg.maxAccumBytes, sizes)
	accumulated, capped := tailWithin(text, grants[0])
	windowed, reasoningCapped := tailWithin(reasoning, grants[1])
	capped = capped || reasoningCapped
	for i := range calls {
		args, argsCapped := tailWithin(calls[i].Arguments, grants[i+2])
		calls[i].Arguments = args
		capped = capped || argsCapped
	}
	return accumulated, windowed, calls, capped
}

// shareBudget divides total across sizes so that no field starves another. The
// shortest field is served first out of an equal share of what is left, and
// whatever it leaves behind widens the share of every field after it, so the
// grants sum to at most total and a field is cut only once every shorter one
// has been carried whole.
func shareBudget(total int, sizes []int) []int {
	order := make([]int, len(sizes))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return cmp.Compare(sizes[a], sizes[b]) })
	grants := make([]int, len(sizes))
	remaining, unserved := total, len(sizes)
	for _, i := range order {
		grants[i] = min(sizes[i], remaining/unserved)
		remaining -= grants[i]
		unserved--
	}
	return grants
}

// tailWithin keeps the last limit bytes of s, advanced to the next rune
// boundary, and reports whether anything was dropped.
func tailWithin(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	tail := s[len(s)-limit:]
	for len(tail) > 0 && !utf8.RuneStart(tail[0]) {
		tail = tail[1:]
	}
	return tail, true
}

// blockFailure resolves streaming.on_error for a block the client is already
// reading. fail_closed can no longer be a clean status code, so it is the same
// stop a block verdict is; fail_open releases and counts, because a guard that
// is failing is not a reason to hold text indefinitely.
func (g *streamGuard) blockFailure(err error) {
	g.failures++
	if g.cfg.onError == streamFailClosed {
		g.stopStream(nil)
		return
	}
	g.degrade(degradeGuardTimeout)
	g.clearedIdx = len(g.produced)
	if g.logger != nil {
		g.logger.Warn("stream block inspection failed; releasing the block",
			slog.Int("consecutive_failures", g.failures),
			slog.String("error", err.Error()))
	}
	if g.failures >= maxConsecutiveFailures {
		g.retire(fallbackSegmentationUnavail)
	}
}

// retire stops calling for the rest of the stream and releases what is held.
// The buffered post_response pass still runs over the whole response, so the
// audit trail survives even though enforcement no longer does.
func (g *streamGuard) retire(reason string) {
	g.silenced = true
	g.fallbackReason = reason
	g.clearedIdx = len(g.produced)
	if g.logger != nil {
		g.logger.Warn("stream segmentation retired",
			slog.String("fallback_reason", reason),
			slog.String("format", string(g.source)))
	}
}

func (g *streamGuard) stopStream(outcome *appplugins.SegmentOutcome) {
	g.stopped = true
	if g.logger == nil {
		return
	}
	kind := string(g.cfg.onError)
	if outcome != nil {
		kind = outcome.Type
	}
	g.logger.Warn("stream stopped after the head by a block verdict",
		slog.Int("seq", g.seq),
		slog.Int("released_events", g.releasedIdx),
		slog.String("type", kind))
}

func (g *streamGuard) degrade(reason string) {
	if g.degradedReason == reason {
		return
	}
	g.degradedReason = reason
	if g.logger != nil {
		g.logger.Warn("stream inspection degraded",
			slog.String("degraded_reason", reason),
			slog.String("format", string(g.source)))
	}
}

// flush reports whether the consumer is still pulling.
//
// A fully released event drops its wire lines. They are the bulk of what the
// guard holds — a 100k-token response is ~400 KB of text but 10-15 MB of SSE
// wire — and wrapStreamWithPostResponse is already buffering the same released
// bytes behind its own 8 MiB cap, so keeping them here makes the guard the
// unbounded half of an otherwise bounded path. Nothing reads them again: B8's
// cut forward works on produced[releasedIdx:], the tail, which this never
// touches. g.text keeps growing — Accumulated and sentChars are built from it.
func (g *streamGuard) flush(yield func([]byte, error) bool) bool {
	for _, ev := range g.produced[g.releasedIdx:g.clearedIdx] {
		for _, line := range ev.lines {
			if !yield(line, nil) {
				return false
			}
		}
		ev.lines = nil
		g.releasedIdx++
	}
	if g.releasedIdx == len(g.produced) {
		g.held = 0
	}
	return true
}

// Now and GuardIdle make the guard the block gate's clock. GuardIdle is always
// true because the loop issues its call inline: the gate is consulted between
// calls and never during one, so one call in flight is a property of the
// loop's shape rather than something the gate has to be told.
func (g *streamGuard) Now() time.Time { return g.now() }

func (g *streamGuard) GuardIdle() bool { return true }

func (g *streamGuard) remainder() iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		defer g.stop()
		if g.srcErr != nil {
			yield(nil, g.srcErr)
			return
		}
		for !g.exhausted {
			line, err, ok := g.next()
			if !ok {
				return
			}
			if !yield(line, err) {
				return
			}
		}
	}
}

// toolCallDigest folds tool-call deltas into whole calls by index, so a segment
// carries arguments a guard can read rather than the fragments they arrived in.
type toolCallDigest struct {
	order []int
	byIdx map[int]*adapter.CanonicalToolCall
}

func (d *toolCallDigest) merge(deltas []adapter.StreamToolCallDelta) {
	for _, delta := range deltas {
		if d.byIdx == nil {
			d.byIdx = make(map[int]*adapter.CanonicalToolCall)
		}
		call, ok := d.byIdx[delta.Index]
		if !ok {
			call = &adapter.CanonicalToolCall{}
			d.byIdx[delta.Index] = call
			d.order = append(d.order, delta.Index)
		}
		if delta.ID != "" {
			call.ID = delta.ID
		}
		if delta.Kind != "" {
			call.Kind = delta.Kind
		}
		if delta.Name != "" {
			call.Name = delta.Name
		}
		call.Arguments += delta.ArgumentsDelta
	}
}

func (d *toolCallDigest) calls() []adapter.CanonicalToolCall {
	if len(d.order) == 0 {
		return nil
	}
	out := make([]adapter.CanonicalToolCall, 0, len(d.order))
	for _, idx := range d.order {
		out = append(out, *d.byIdx[idx])
	}
	return out
}
