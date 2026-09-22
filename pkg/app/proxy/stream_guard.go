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

// guardCodec is the adapter registry as the guard uses it: the segmenter's
// decode direction, plus the encode direction a cut terminator is synthesised
// through.
type guardCodec interface {
	streamCodec
	EncodeStreamChunkFor(canonical *adapter.CanonicalStreamChunk, source adapter.Format) ([][]byte, error)
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

	// streamCutReason is the canonical finish reason a cut terminator carries.
	// Every source adapter maps it to its own dialect — Anthropic refusal,
	// Gemini SAFETY, Cohere ERROR, Responses response.incomplete — and
	// StreamBlockedEvent constrains the error channel to the same closed set.
	streamCutReason = "content_filter"

	streamMaskedMessage = "Response blocked: guardrail masking could not be applied to this stream."
	// streamMaskedType marks a block the policy did not ask for: the guard
	// returned a mask the stream path could not write into the held events, so
	// it escalated. rewrite is the whole account of when that happens. A client
	// seeing this is being denied something a buffered call would have received
	// with the sensitive span masked.
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
	// cutDrainDeadline bounds the background drain a cut leaves behind. Usage
	// rides the last chunk, so a stream that is still generating when the
	// deadline expires is charged nothing — but an upstream connection held
	// open for the rest of a long generation nobody will read is the worse of
	// the two, and the deadline is what makes the drain a bounded cost.
	cutDrainDeadline = 30 * time.Second
)

// Why a stream stopped being inspected the way the policy asked. A degrade is
// per block and recoverable; a fallback retires the block loop for the rest of
// the stream. They are aliases of the shared tokens so the strings the guard
// records and the strings the plugin publishes cannot drift.
const (
	degradeAccumulationCap      = appplugins.StreamDegradeAccumulationCap
	degradeGuardTimeout         = appplugins.StreamDegradeGuardTimeout
	fallbackSegmentationUnavail = appplugins.StreamFallbackSegmentationUnavail
	fallbackClientDisconnected  = appplugins.StreamFallbackClientDisconnected
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
	codec  guardCodec
	in     appplugins.StageInput
	cfg    streamGuardConfig
	source adapter.Format
	logger *slog.Logger
	now    func() time.Time
	// drain hands the rest of an abandoned upstream to a background reader, so
	// a cut still accounts the usage the last chunk carries. A nil drain cuts
	// the same way and charges nothing.
	drain func(iter.Seq2[[]byte, error])
	// drained is closed by that reader when it is done. It is the only
	// happens-before edge between the drain's writes to req.Metadata and the
	// stages that read them.
	drained chan struct{}

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

	released releasedAnchor
	gate     *blockGate
	seq      int
	// inspected is the accumulated text the last call carried, which a
	// transform verdict replaces whole. It is a suffix of the produced text and
	// not always the whole of it: past the accumulation cap a call carries a
	// tail window, and the bytes in front of that window are text no verdict of
	// that block speaks for.
	inspected      string
	sentChars      int
	finalSent      bool
	failures       int
	silenced       bool
	stopped        bool
	handedOff      bool
	cutMessage     string
	degradedReason string
	fallbackReason string

	// What the stream cost, handed to the chain once on the closing segment.
	// holdStart is the moment the oldest unreleased event arrived, so the added
	// latency it accumulates is what the client waited for held bytes rather
	// than what the chain spent: the first is always the larger, and it is the
	// one the response leg makes client-visible for the first time.
	callFailures  int
	guardTotal    time.Duration
	guardMax      time.Duration
	addedLatency  time.Duration
	holdStart     time.Time
	releasedChars int
	cutAtEval     int
	cutOffset     int
	closed        bool

	// findings is every finding fingerprint the chain reported over this
	// stream, in first-seen order and tagged with the entry that reported it,
	// and seenFindings is the membership test behind it. Alert-only never cuts
	// and every call carries the whole accumulated text, so a finding that
	// trips one block trips every block after it; the set is what makes the
	// inspector publish it once. It hangs off the guard because the guard is
	// the one object whose lifetime is the stream's, so nothing has to remember
	// to sweep it.
	findings     []appplugins.StreamFinding
	seenFindings map[appplugins.StreamFinding]struct{}
}

func newStreamGuard(
	runner segmentRunner,
	codec guardCodec,
	source adapter.Format,
	in appplugins.StageInput,
	cfg streamGuardConfig,
	logger *slog.Logger,
) *streamGuard {
	return &streamGuard{
		runner: runner,
		seg:    newSegmenter(codec, source),
		codec:  codec,
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
		g.close(spanCtx)
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
	if g.releasedIdx == len(g.produced) && g.holdStart.IsZero() {
		g.holdStart = g.now()
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
	outcome, err := g.call(ctx, g.nextSegment())
	if err != nil {
		return g.headFailure(err)
	}
	if outcome != nil && outcome.Block {
		g.markCut()
		return blockedHeadError(g.source, outcome)
	}
	// Nothing has been released at the head, so the one trigger rewrite cannot
	// fire here is the released-text one; every other reason it refuses applies
	// to the head block as it does to any other. Escalating still costs a status
	// code rather than a truncated body, which is the one advantage the head
	// has over every block after it.
	if outcome != nil && outcome.HasTransform && !g.rewrite(outcome) {
		g.markCut()
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
		// A cut hands the pull coroutine to the background drain, which closes
		// it when it is done. Stopping it here as well would cut the drain off
		// mid-read and lose the usage it exists to recover.
		defer func() {
			if !g.handedOff {
				g.stop()
			}
		}()
		defer cancel()
		// Registered last so it runs first: the closing segment is the only
		// write of the per-stream aggregate, and it has to be issued while the
		// stream context is still live, whatever ended the stream — the end of
		// the source, a cut, a retired block loop, or a client that stopped
		// pulling.
		defer g.close(streamCtx)
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
	for {
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
		if g.stopped {
			g.cut(yield)
			return
		}
		g.gate.reset()
		if !g.flush(yield) {
			return
		}
	}
	g.admit(g.seg.flush())
	g.inspect(ctx)
	if g.stopped {
		g.cut(yield)
		return
	}
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
// stops the stream where it stands and the loop cuts it with the terminator
// the caller's dialect carries for a content filter.
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
	outcome, err := g.call(ctx, g.nextSegment())
	if err != nil {
		g.blockFailure(err)
		return
	}
	g.failures = 0
	if outcome != nil && (outcome.Block || (outcome.HasTransform && !g.rewrite(outcome))) {
		g.stopStream(outcome)
		return
	}
	g.clearedIdx = len(g.produced)
}

// rewrite applies a transform verdict to the accumulated buffer and reports
// whether it could. One rule decides it: the masked buffer may differ from the
// produced one only inside text the guard is still holding, and the held events
// that carried that text must be re-encodable from the text alone. Held text is
// the only text the guard can still change on the wire, and a re-encode is the
// only way it can change it.
//
// Everything else stops the stream rather than release text the policy asked to
// mask. The two the rule is written for are a span that reaches into what the
// client has already read — those bytes are gone, and §3.5 is that the cut goes
// forward at the release pointer — and a span the text buffer does not carry,
// which is in reasoning or in tool-call arguments, where a mask would put
// assistant text where a thought or a JSON argument stood. rewritableHold
// carries the rest, and two operational refusals sit here: a call that
// inspected no window of the buffer names no span for the verdict to replace,
// and an encode that produced nothing has no event to put the mask in.
func (g *streamGuard) rewrite(outcome *appplugins.SegmentOutcome) bool {
	produced := g.text.String()
	if g.inspected == "" || !strings.HasSuffix(produced, g.inspected) {
		return false
	}
	masked := strings.TrimSuffix(produced, g.inspected) + outcome.Transformed
	// A verdict that left the buffer byte-identical masked something the buffer
	// cannot see. It reads the same as a verdict re-flagging a mask the guard
	// itself already applied and handing it back unchanged, and the verdict
	// names no offsets to tell them apart, so both end the stream: releasing on
	// the wrong reading releases exactly the content the policy asked to mask.
	// Finding offsets on SegmentOutcome are what would separate them (§11).
	if masked == produced {
		return false
	}
	first, ok := g.rewritableHold()
	if !ok || !strings.HasPrefix(masked, g.releasedText()) {
		return false
	}
	return g.remask(masked, first)
}

// rewritableHold reports whether the held events can carry a mask at all, and
// names the one the masked text would collapse onto. Three things say they
// cannot, and none of them can be read off the verdict, which names no offsets
// and replaces the accumulated text as a whole.
//
// A held event carrying reasoning or tool-call deltas is refused whether or not
// it carries text of its own. The narrow condition — only an event carrying
// both — would be enough to keep a re-encode from dropping a thought or a JSON
// argument, and it would keep masking working on reasoning streams, where a
// pure thinking_delta is left untouched. It is not taken because the single
// Transformed field cannot say which field the mask fell in: a verdict over a
// payload that carried text, reasoning and arguments hands back one text, and
// rewriting the text on that basis assumes the mask fell entirely in text,
// which the contract does not say. The cost is stated rather than hidden — a
// transform verdict on an extended-thinking or reasoning_content provider is
// always a cut, never a mask — and it is the conservative direction: a cut
// announces itself, an unmasked release does not.
//
// A held event whose text rides with a finish reason, a usage report or a
// structural mark is refused because the re-encode carries none of them.
// Gemini's last chunk is one data: line holding the delta, the finish reason
// and the usage metadata at once, and Gemini has no [DONE]: re-encoding it from
// its text would end the stream on a bare text delta.
//
// Held text spanning more than one block or item is refused because the
// collapse is onto one event. Dividing the mask back across the events it
// arrived in is the fragment splicing §2.6 rejected, so the text of a later
// block would move into an earlier one and leave an empty text block behind —
// which reconstructs the same string but which the Messages API rejects on
// input, so an agent replaying the turn gets a 400 it did not get before.
func (g *streamGuard) rewritableHold() (int, bool) {
	first, last := -1, -1
	for i := g.releasedIdx; i < len(g.produced); i++ {
		ev := g.produced[i]
		if ev.reasoning != "" || len(ev.toolCalls) > 0 {
			return 0, false
		}
		if ev.text == "" {
			continue
		}
		if ev.beyondText {
			return 0, false
		}
		if first < 0 {
			first = i
		}
		last = i
	}
	if first < 0 {
		return 0, false
	}
	for _, ev := range g.produced[first+1 : last+1] {
		if ev.mark.op != markNone {
			return 0, false
		}
	}
	return first, true
}

// releasedText is the text the client has already read, which is what a mask
// may not reach into. It is rebuilt from the events rather than counted,
// because a rewrite changes the length of everything behind it and a counter
// kept across one would have to be corrected on every path a rewrite can fail.
func (g *streamGuard) releasedText() string {
	var released strings.Builder
	for _, ev := range g.produced[:g.releasedIdx] {
		released.WriteString(ev.text)
	}
	return released.String()
}

// remask replaces the accumulated buffer and the wire bytes of the held events
// that carried the text it changed. Nothing else is re-encoded: released events
// have already gone out byte for byte, held events with no text of their own
// keep the bytes they arrived as, and what the source has not yielded yet is
// untouched. The segmenter still has no encode direction — this is the guard's
// own, and it is reached only by a transform verdict.
//
// The held text is collapsed onto first, the first held event that carried any,
// rather than divided back across the events it arrived in. The verdict
// replaces the buffer whole and says nothing about where inside it the mask
// fell, so a per-event division would be the fragment splicing §2.6 rejected.
func (g *streamGuard) remask(masked string, first int) bool {
	held := strings.TrimPrefix(masked, g.releasedText())
	anchor := g.released
	for _, ev := range g.produced[g.releasedIdx:first] {
		anchor.apply(ev.mark)
	}
	lines, err := g.maskLines(held, anchor)
	if err != nil || (held != "" && len(lines) == 0) {
		if g.logger != nil {
			g.logger.Warn("stream mask could not be encoded; escalating to a cut",
				slog.String("format", string(g.source)),
				slog.Any("error", err))
		}
		return false
	}
	for _, ev := range g.produced[first:] {
		if ev.text == "" {
			continue
		}
		ev.lines, ev.text = nil, ""
	}
	g.produced[first].lines, g.produced[first].text = lines, held
	g.text.Reset()
	g.text.WriteString(masked)
	g.sentChars = g.text.Len()
	g.inspected = ""
	return true
}

// maskLines encodes the held text as one event in the caller's dialect. The
// anchor is the structure the client can see open at the point the event sits,
// which is the released one advanced over the held events in front of it, and
// both axes it carries are named for the same reason terminator names them: an
// Anthropic text_delta names the content block it belongs to and a Responses
// delta names the output item, and naming neither attaches the masked text to
// block 0 of an unidentified item — which a client keyed on item_id does not
// attach at all.
func (g *streamGuard) maskLines(held string, anchor releasedAnchor) ([][]byte, error) {
	if held == "" {
		return nil, nil
	}
	return g.codec.EncodeStreamChunkFor(&adapter.CanonicalStreamChunk{
		ID:                g.seg.anchor.id,
		Model:             g.seg.anchor.model,
		Delta:             held,
		ContentBlockIndex: anchor.blockIndex,
		OpenItem:          anchor.openItem,
	}, g.source)
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
	g.inspected = accumulated
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

// call is the one place a verdict is asked for, so it is the one place the cost
// of asking is measured. The clock covers the whole chain rather than the
// engine RTT alone: what the response leg newly makes client-visible is the
// hold, and the hold lasts as long as the call the guard is waiting on.
func (g *streamGuard) call(
	ctx context.Context,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentOutcome, error) {
	started := g.now()
	outcome, err := g.runner.RunStreamSegment(ctx, g.in, seg)
	elapsed := g.now().Sub(started)
	g.guardTotal += elapsed
	if elapsed > g.guardMax {
		g.guardMax = elapsed
	}
	if err != nil {
		g.callFailures++
		return nil, err
	}
	g.remember(outcome)
	return outcome, nil
}

// remember folds one block's fingerprints into the stream's set. It sits here
// rather than in the block loop so the head block, which is evaluated on its
// own path, contributes on the same terms as every block after it.
func (g *streamGuard) remember(outcome *appplugins.SegmentOutcome) {
	if outcome == nil || len(outcome.Fingerprints) == 0 {
		return
	}
	if g.seenFindings == nil {
		g.seenFindings = make(map[appplugins.StreamFinding]struct{}, len(outcome.Fingerprints))
	}
	for _, fp := range outcome.Fingerprints {
		if _, ok := g.seenFindings[fp]; ok {
			continue
		}
		g.seenFindings[fp] = struct{}{}
		g.findings = append(g.findings, fp)
	}
}

// The offset is what the client had already received, not what the provider had
// produced: it is the exposure the cut did not prevent, which is the number an
// operator sets min_chars_between_evals against. On a stream an earlier block
// rewrote, the characters it counts are the masked ones the client actually
// read rather than the ones the provider sent, which is the same answer to the
// same question and not a coincidence worth relying on elsewhere.
func (g *streamGuard) markCut() {
	if g.cutAtEval != 0 {
		return
	}
	g.cutAtEval = g.seq
	g.cutOffset = g.releasedChars
}

// report is the guard's account of the stream, handed to the chain once. It is
// built here and published by the inspector because only the guard sees every
// path the stream can end on, and only the inspector owns an event to write to.
func (g *streamGuard) report() appplugins.StreamReport {
	return appplugins.StreamReport{
		Evals:           g.seq,
		GuardCalls:      g.seq - g.callFailures,
		GuardLatency:    g.guardTotal,
		GuardLatencyMax: g.guardMax,
		AddedLatency:    g.addedLatency,
		CutAtEval:       g.cutAtEval,
		CutOffsetChars:  g.cutOffset,
		FinalPass:       g.finalSent,
		DegradedReason:  g.degradedReason,
		FallbackReason:  g.fallbackReason,
	}
}

// close issues the closing segment. It asks for no verdict and carries no text:
// it exists so the aggregate is written exactly once, on every path a stream can
// end on, including the ones that never reach a final block. Its own cost is
// deliberately outside the report it carries.
func (g *streamGuard) close(ctx context.Context) {
	if g.closed {
		return
	}
	g.closed = true
	if _, err := g.runner.RunStreamSegment(ctx, g.in, appplugins.StreamSegment{
		StreamID: g.streamID,
		Seq:      g.seq,
		Closing:  true,
		Report:   g.report(),
		Findings: g.findings,
	}); err != nil && g.logger != nil {
		g.logger.Warn("stream aggregate was not published",
			slog.String("format", string(g.source)),
			slog.String("error", err.Error()))
	}
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
	g.markCut()
	g.cutMessage = cutMessage(outcome)
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

// cutMessage names the incident on the error channel. The dialects have one
// free-form slot between them and the reason already occupies it, so the three
// reasons a stream stops — rejected, unverifiable, and a mask the stream path
// cannot apply — are told apart by the message alone.
func cutMessage(outcome *appplugins.SegmentOutcome) string {
	switch {
	case outcome == nil:
		return streamUnverifiableMessage
	case outcome.Block && outcome.Message != "":
		return outcome.Message
	case outcome.Block:
		return streamBlockMessage
	default:
		return streamMaskedMessage
	}
}

// cut is regime B. The status went out with the head, so the only honest
// ending left is the one the caller's dialect has for a content filter: the
// finish-reason terminator first, and the blocked event after it, never
// instead of it — an error event on its own leaves an Anthropic content block
// or a Responses output item open for good.
//
// What the guard still holds is dropped where it stands. The payload is
// cumulative, so the verdict can name text released blocks ago, and a wire the
// client has already read cannot be retracted: the cut goes forward at the
// release pointer and one block is the exposure bound.
func (g *streamGuard) cut(yield func([]byte, error) bool) {
	g.drainForUsage()
	// Releasing the wire bytes of everything the cut drops is a hint to the
	// collector, not behaviour: nothing reads produced[releasedIdx:] again. It
	// is here because the tail of a long response is megabytes of SSE the
	// guard would otherwise keep alive until the request object is collected.
	for _, ev := range g.produced[g.releasedIdx:] {
		ev.lines = nil
	}
	for _, line := range g.cutLines() {
		if !yield(line, nil) {
			return
		}
	}
}

// cutLines is the whole cut on the wire, in one dialect.
//
// [DONE] is unconditional here, unlike in adaptStream, which re-emits it only
// on the cross-format branch (provider_stream.go:164) because on a passthrough
// the upstream's own sentinel comes through by itself. On a cut it never
// arrives: the upstream is abandoned and what it still had to say is dropped or
// drained, so the guard owes the sentinel to every source whose wire ends on
// one.
//
// Cohere is the one dialect that gets no blocked event. Its streamed-response
// union has no error member, so StreamBlockedEvent falls through to the
// OpenAI-shaped default — an object with no "type" discriminant on a wire whose
// SDK parses every event as a StreamedChatResponseV2. ERROR on message-end
// carries the whole signal there, which is what canonicalFinishToCohere says.
func (g *streamGuard) cutLines() [][]byte {
	lines, err := g.codec.EncodeStreamChunkFor(g.terminator(), g.source)
	if err != nil {
		// StreamBlockedEvent is documented as never travelling alone, and
		// without a terminator in front of it that is exactly what it would be:
		// on Anthropic and Responses it leaves the block and the item the cut
		// interrupted open for good. The bare sentinel is the most a dialect
		// that has one can still be told honestly.
		if g.logger != nil {
			g.logger.Warn("stream cut terminator could not be encoded",
				slog.String("format", string(g.source)),
				slog.String("error", err.Error()))
		}
		return g.cutDoneLines()
	}
	if !adapter.IsSameWireFormat(g.source, adapter.FormatCohere) {
		lines = append(lines, adapter.StreamBlockedEvent(g.source, streamCutReason, g.cutMessage)...)
	}
	return append(lines, g.cutDoneLines()...)
}

// cutDoneLines is the [DONE] sentinel for the sources whose wire ends on it and
// nothing for the rest. Mistral is named on its own because normalizeFormat
// does not fold it into FormatOpenAI even though the rest of the gateway treats
// it as OpenAI-family (format.go:113,126), and a Mistral SSE client waits for
// [DONE] rather than for the connection to close.
func (g *streamGuard) cutDoneLines() [][]byte {
	if adapter.IsSameWireFormat(g.source, adapter.FormatOpenAI) || g.source == adapter.FormatMistral {
		return sseDoneLines()
	}
	return nil
}

// terminator is the chunk a cut ends on: the identity of the response, the
// content-filter finish reason every source adapter maps into its own dialect,
// and the structure the client still has open.
//
// The structure comes from the released side, not from what the guard has read.
// The cut drops produced[releasedIdx:], so those events never reached anyone: a
// terminator built from them closes a block the client never saw announced and
// leaves the one it is looking at open for good.
func (g *streamGuard) terminator() *adapter.CanonicalStreamChunk {
	chunk := adapter.CompletionsTerminalStreamChunk(
		&adapter.CanonicalStreamChunk{ID: g.seg.anchor.id, Model: g.seg.anchor.model},
		streamCutReason,
	)
	chunk.ContentBlockIndex = g.released.blockIndex
	chunk.ContentBlockClosed = !g.released.blockOpen
	chunk.OpenItem = g.released.openItem
	return chunk
}

// releasedAnchor is the structure the client can still see open, built from the
// events the guard actually yielded. cutAnchor names the response; this names
// what is unterminated on the wire in front of the caller.
//
// It tracks open and closed rather than the last index seen, which is the only
// way to answer the two cases a running index gets wrong: a released prefix that
// already ended on a content_block_stop needs no second stop, and an item the
// upstream closed inside the released prefix must not be closed again.
type releasedAnchor struct {
	blockOpen  bool
	blockIndex int
	openItem   *adapter.StreamOpenItem
}

func (a *releasedAnchor) apply(m streamMark) {
	switch m.op {
	case markOpenBlock:
		a.blockOpen, a.blockIndex = true, m.index
	case markCloseBlock:
		// A stop for some other index is an upstream shape the guard does not
		// model; forgetting the open block on it would leave it open.
		if a.blockOpen && a.blockIndex == m.index {
			a.blockOpen = false
		}
	case markOpenItem:
		item := m.item
		a.openItem = &item
	case markCloseItem:
		if a.openItem != nil && a.openItem.Index == m.index {
			a.openItem = nil
		}
	case markNone:
	}
}

// drainForUsage keeps reading the abandoned upstream in the background so the
// usage the last chunk carries is still charged. observeChunk runs inside
// adaptStream, upstream of the guard, so usage is recorded when a line is read
// and not when it is released: draining is enough for streamObserver to see it
// and to populate req.Metadata["usage"].
//
// It is also the point at which the request grows a second writer. streamObserver
// writes that map from the drain's goroutine, so everything downstream that
// reads it — post_response, and token_rate_limiter through it — has to wait for
// drained, which cutRemainder closes when it is done. Reading the map before
// then is a concurrent map read and write, and charging from it before then
// charges nothing at all, because usage has not arrived yet.
//
// The drain takes the pull coroutine over, which is what handedOff records: two
// owners would stop it twice and cut the drain off mid-read.
func (g *streamGuard) drainForUsage() {
	if g.drain == nil {
		return
	}
	g.handedOff = true
	g.drained = make(chan struct{})
	g.drain(g.cutRemainder(g.drained))
}

// cutBarrier is closed once the drain a cut handed the upstream to has finished
// reading it. It is nil when no cut handed anything off, which is every stream
// that ended on its own.
//
// It must be read after the returned sequence is exhausted: the cut runs on the
// stream's own goroutine, so a consumer whose range loop has ended has seen the
// field written.
func (g *streamGuard) cutBarrier() <-chan struct{} { return g.drained }

// cutRemainder is the rest of the source, read on the drain's goroutine while
// the stream's own goroutine is still writing the terminator. It touches no
// guard state for that reason, and it closes drained on the way out so the
// stages that read what the drain accounted can order themselves behind it.
//
// It stops on its own deadline, which is checked between reads: an upstream
// that keeps generating is abandoned within one read of the deadline, but one
// that stalls mid-read holds the goroutine until the transport gives up. That
// is the bound this deadline actually provides.
//
// It yields nothing. Reading is the whole point — usage is recorded where the
// line is read — and drainStream stops at the first line it is handed, because
// releasing the backend connection is all its other callers ask of it. A
// sequence that handed its lines over would therefore drain exactly one.
func (g *streamGuard) cutRemainder(drained chan<- struct{}) iter.Seq2[[]byte, error] {
	next, stop, now := g.next, g.stop, g.now
	until := now().Add(cutDrainDeadline)
	return func(func([]byte, error) bool) {
		defer close(drained)
		defer stop()
		for now().Before(until) {
			if _, _, ok := next(); !ok {
				return
			}
		}
	}
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
	released := g.releasedIdx
	for _, ev := range g.produced[g.releasedIdx:g.clearedIdx] {
		for _, line := range ev.lines {
			if !yield(line, nil) {
				// A consumer that stops pulling is the only disconnect signal
				// there is, and it is worth a token of its own: the stream was
				// inspected as configured right up to the point nobody was
				// reading it any more. It is the least serious of the reasons,
				// though, so a loop that had already retired keeps the reason
				// it retired for.
				if g.fallbackReason == "" {
					g.retire(fallbackClientDisconnected)
				}
				return false
			}
		}
		g.releasedChars += ev.chars()
		// The anchor advances here and only here, because this is where an
		// event becomes something the client has seen. A yield that comes back
		// false stops before the mark is applied, which is correct: those lines
		// did not reach anyone either.
		g.released.apply(ev.mark)
		ev.lines = nil
		g.releasedIdx++
	}
	// The hold clock is charged only where it ends, which is an event reaching
	// the client. A flush the verdict gave nothing to release has not ended
	// anyone's wait, and charging it would count the same wait once per block.
	if released == g.releasedIdx {
		return true
	}
	if !g.holdStart.IsZero() {
		g.addedLatency += g.now().Sub(g.holdStart)
		g.holdStart = time.Time{}
	}
	if g.releasedIdx == len(g.produced) {
		g.held = 0
		return true
	}
	// Whatever the verdict did not cover starts waiting again from here.
	g.holdStart = g.now()
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

// cutAnchor is the identity of the response a synthesised terminator ends.
// Neither field survives on the chunk a cut builds from nothing, and a strict
// OpenAI client rejects a chunk without an id, so both are read off the first
// event that carries them and kept for the cut.
//
// It is filled by the segmenter, the only place that holds a raw payload and
// its decode at the same time.
type cutAnchor struct {
	id    string
	model string
}

func (a *cutAnchor) observe(chunk *adapter.CanonicalStreamChunk) {
	if chunk == nil {
		return
	}
	if a.id == "" {
		a.id = chunk.ID
	}
	if a.model == "" {
		a.model = chunk.Model
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
