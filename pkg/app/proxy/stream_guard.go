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
	"context"
	"iter"
	"log/slog"
	"net/http"
	"strings"

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
)

// maxHeadHeldBytes bounds what the head gate holds. head_chars does not: an
// event the codec cannot decode contributes no inspectable text, so on an
// undecodable stream chars never advances and the head would run to the
// terminal event — de-streaming the whole response onto the live request path.
// A provider line may be 2 MiB (infra/providers/stream.go), so the ceiling is
// tested before each pull and may be exceeded by at most one line.
const maxHeadHeldBytes = 256 << 10

type streamGuardConfig struct {
	headChars int
	onError   streamOnError
}

func (c streamGuardConfig) withDefaults() streamGuardConfig {
	if c.headChars <= 0 {
		c.headChars = defaultHeadChars
	}
	if c.onError != streamFailClosed {
		c.onError = streamFailOpen
	}
	return c
}

// streamGuard holds the head of a streaming response until a verdict covers
// it. produced is every event pulled from the source in arrival order;
// releasedIdx counts the events already handed to the client and clearedIdx
// the events a clean verdict covers, so releasedIdx <= clearedIdx <=
// len(produced) holds after every step.
type streamGuard struct {
	runner segmentRunner
	seg    *segmenter
	in     appplugins.StageInput
	cfg    streamGuardConfig
	source adapter.Format
	logger *slog.Logger

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
	}
}

// Run evaluates the head of the stream before a single byte reaches the client,
// which is the only point at which a violation can still be a real HTTP status:
// finalizeStream has not returned, so status and headers are unset.
//
// It returns the sequence the caller must consume. After a clean verdict that
// is the cleared head replayed byte for byte followed by the rest of the
// source. On a head-gate block it is only the undrained remainder, which the
// caller drains and discards: the source has already been pulled from and
// cannot be ranged a second time.
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
	return g.replay(release), nil
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
			g.terminal = true
			break
		}
	}
	if g.exhausted || g.srcErr != nil || g.held >= maxHeadHeldBytes {
		g.terminal = g.admit(g.seg.flush()) || g.terminal
	}
	return g.evaluate(ctx)
}

// admit records a completed event and reports whether it ended the response. A
// classification failure arrives alongside its event and never instead of it,
// so returning early on the error would drop wire bytes the client is owed.
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
	return ev.unit == unitTerminal
}

func (g *streamGuard) evaluate(ctx context.Context) *appplugins.PluginError {
	if g.clearedIdx == len(g.produced) {
		return nil
	}
	outcome, err := g.runner.RunStreamSegment(ctx, g.in, appplugins.StreamSegment{
		StreamID:    g.streamID,
		Seq:         1,
		Final:       g.terminal || g.exhausted || g.srcErr != nil,
		Text:        g.text.String(),
		Accumulated: g.text.String(),
		Reasoning:   g.reasoning.String(),
		ToolCalls:   g.tools.calls(),
	})
	if err != nil {
		return g.headFailure(err)
	}
	if outcome != nil && outcome.Block {
		return blockedHeadError(g.source, outcome)
	}
	g.clearedIdx = len(g.produced)
	return nil
}

// headFailure resolves streaming.on_error. The plugin hands a configurable
// failure back as an error precisely so that it is resolved here: only the
// guard knows that at the head nothing is committed, which is what makes
// fail_closed a clean status code instead of a truncated body.
func (g *streamGuard) headFailure(err error) *appplugins.PluginError {
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

// replay writes the events the verdict cleared, in arrival order and as the
// bytes they arrived as, and then hands the rest of the source through. Nothing
// is re-encoded: a re-encode would reorder usage, provider extensions and
// comments on a wire that is byte-exact by contract.
func (g *streamGuard) replay(release func()) iter.Seq2[[]byte, error] {
	rest := g.remainder()
	return func(yield func([]byte, error) bool) {
		defer release()
		defer g.stop()
		for _, ev := range g.produced[g.releasedIdx:g.clearedIdx] {
			for _, line := range ev.lines {
				if !yield(line, nil) {
					return
				}
			}
			g.releasedIdx++
		}
		rest(yield)
	}
}

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
