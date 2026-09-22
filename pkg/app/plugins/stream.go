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

package plugins

import (
	"context"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

// StreamSegment is one closed block of a streaming response, handed to a
// StreamInspector for a verdict. Accumulated is a contiguous prefix of the text
// the provider has produced, never of the text already released to the client:
// building it from released text would hide a finding split across the block in
// flight and the one being inspected. Text is the delta of this block alone;
// Reasoning and ToolCalls are cumulative like Accumulated, not per-block
// deltas. Truncated says the guard hit its accumulation cap and swapped
// Accumulated from a full prefix to a tail window, so the plugin can carry the
// distinction onto the wire envelope the engine reads.
type StreamSegment struct {
	StreamID    string
	Seq         int
	Final       bool
	Truncated   bool
	Text        string
	Accumulated string
	Reasoning   string
	ToolCalls   []adapter.CanonicalToolCall
	// Closing marks the one segment that carries no text and asks for no
	// verdict. The guard issues it once, when the stream is over on every path
	// it can end on, so an inspector has a single point at which to publish
	// what the whole stream cost. Span.SetExtras overwrites rather than merges,
	// so a per-block write would destroy the previous one, and the paths that
	// never reach a final block — a cut, a retired block loop, a client that
	// left — would otherwise publish nothing at all.
	Closing bool
	// Report is the guard's own account of the stream. Only the guard sees
	// every path the stream can take and holds the clock the client waited on,
	// so it measures and the inspector publishes. It is filled on the closing
	// segment and empty on every other.
	Report StreamReport
	// ReportsStream marks the one entry on a closing segment that is asked to
	// publish what describes the whole stream rather than its own share of it.
	// Every entry writes its own span, but an instrument keyed on the response
	// — how many calls it cost, how long it was held, how it ended — would
	// count one response once per policy if every entry recorded it.
	ReportsStream bool
}

// StreamReport is what one streamed response cost, as the component that held
// the bytes measured it.
//
// Evals counts the blocks handed to the chain; GuardCalls counts the ones that
// came back with a verdict, so the difference is failures. GuardLatency is the
// time spent inside the chain and AddedLatency the time bytes spent held before
// reaching the client. The two measure different things and neither bounds the
// other: AddedLatency is charged only where a flush releases something, so a
// stream cut at the head reports none of it against a real hold.
//
// The guard fills it for the whole chain, and the executor narrows it per entry
// before an inspector sees it: GuardLatency becomes that entry's own share and
// the cut fields are cleared on every entry but the one whose verdict cut. The
// rest — Evals, GuardCalls, GuardLatencyMax, AddedLatency, FinalPass and the
// two reasons — describe the stream, not the entry, and reach every entry
// unchanged.
type StreamReport struct {
	Evals           int
	GuardCalls      int
	GuardLatency    time.Duration
	GuardLatencyMax time.Duration
	AddedLatency    time.Duration
	CutAtEval       int
	CutOffsetChars  int
	FinalPass       bool
	DegradedReason  string
	FallbackReason  string
}

// Stable tokens for why a stream stopped being inspected the way the policy
// asked. A degrade is per block and recoverable; a fallback retires the block
// loop for the rest of the stream.
//
// They are declared here rather than in either package that uses them because
// the guard produces them and the plugin publishes them onto the event, and the
// two must not drift: these strings land in ClickHouse, so renaming one after
// release is a data migration rather than a code change.
const (
	StreamDegradeAccumulationCap      = "accumulation_cap"
	StreamDegradeGuardTimeout         = "guard_timeout"
	StreamFallbackSegmentationUnavail = "segmentation_unavailable"
	StreamFallbackClientDisconnected  = "client_disconnected"
)

// SegmentVerdict is a plugin's answer for one StreamSegment. Transformed, when
// HasTransform is set, replaces the whole of StreamSegment.Accumulated: the
// caller owns a single contiguous buffer and rewrites it in place, so splicing
// per-segment fragments back together is never required.
type SegmentVerdict struct {
	Block        bool
	Type         string
	Message      string
	HasTransform bool
	Transformed  string
	Fingerprints []string
}

// StreamOptions is the streaming configuration of the entry that opted in.
// HeadChars and OnError live in the plugin's own settings schema, so they
// travel with the opt-in rather than being re-read by a caller that cannot
// parse them: an operator who sets streaming.on_error to fail_closed must not
// silently get fail_open. The block-loop knobs travel the same way and for the
// same reason: MinCharsBetweenEvals floors how often a block closes,
// MaxHoldMS ceilings how long one may be held, and MaxAccumulatedBytes bounds
// what a single call carries before the payload degrades to a tail window.
type StreamOptions struct {
	HeadChars            int
	OnError              string
	MinCharsBetweenEvals int
	MaxHoldMS            int
	MaxAccumulatedBytes  int
}

// StreamInspector is the opt-in a plugin declares to be consulted per block of
// a streaming response. A plugin that does not implement it is absent from the
// stream chain and still runs at the fixed stages, so the capability extends
// one plugin at a time, the way ScopeInertSafe does.
//
// Implementing the interface is not by itself the opt-in: StreamSettings reads
// the policy's settings and decides. A plugin whose streaming block is
// disabled yields no stream chain at all, so an existing policy costs nothing.
//
// InspectSegment must return promptly and without error on a segment whose
// Closing flag is set, whatever it makes of the report it carries. That call is
// the last point at which any inspector in the chain can write to its span, it
// happens on a client's critical path with the response already sent, and no
// verdict is read from it.
type StreamInspector interface {
	InspectSegment(ctx context.Context, in ExecInput, seg StreamSegment) (*SegmentVerdict, error)
	StreamSettings(settings map[string]any) (bool, StreamOptions)
}

// SegmentOutcome is the executor's consolidated answer across the chain for one
// StreamSegment.
type SegmentOutcome struct {
	Block        bool
	Type         string
	Message      string
	HasTransform bool
	Transformed  string
	Fingerprints []string
}

// streamInspector reports whether the descriptor opted in, and hands back the
// interface. A descriptor that does not implement StreamInspector is denied,
// so no plugin joins the stream chain by omission.
func streamInspector(d PluginDescriptor) (StreamInspector, bool) {
	insp, ok := d.(StreamInspector)
	return insp, ok
}

type streamSpansKey struct{}

type streamSpans struct {
	mu     sync.Mutex
	events map[string]*metrics.EventContext
	spent  map[string]time.Duration
	cutBy  map[string]string
}

// NewStreamSpanContext derives a context carrying the plugin spans of a single
// stream, and the func that ends them. A stream is inspected once per block, so
// without this holder a long response would publish one span per block instead
// of one per participating policy. A context without it opens no span at all.
//
// It takes an async hold on the request trace, as the post_response stage does:
// the trace emits on its last Done, so a span ended after that point is dropped
// or lands with zero latency. The returned func publishes the spans and
// releases the hold, and is safe to call more than once.
func NewStreamSpanContext(ctx context.Context) (context.Context, func()) {
	spans := &streamSpans{
		events: make(map[string]*metrics.EventContext),
		spent:  make(map[string]time.Duration),
		cutBy:  make(map[string]string),
	}
	rt := trace.FromContext(ctx)
	if rt != nil {
		rt.AddAsync()
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			spans.publish()
			if rt != nil {
				rt.Done()
			}
		})
	}
	return context.WithValue(ctx, streamSpansKey{}, spans), release
}

func streamSpansFrom(ctx context.Context) *streamSpans {
	if ctx == nil {
		return nil
	}
	spans, _ := ctx.Value(streamSpansKey{}).(*streamSpans)
	return spans
}

func (s *streamSpans) eventFor(ctx context.Context, seg StreamSegment, entry chainEntry) *metrics.EventContext {
	if s == nil {
		return nil
	}
	rt := trace.FromContext(ctx)
	if rt == nil {
		return nil
	}
	key := spanKey(seg, entry)
	s.mu.Lock()
	defer s.mu.Unlock()
	if event, ok := s.events[key]; ok {
		return event
	}
	span := rt.StartSpan(trace.SpanPlugin, entry.plugin.Name())
	span.SetStage(string(policy.StagePreResponse))
	event := metrics.NewEventContext(span)
	event.SetMode(string(entry.mode))
	s.events[key] = event
	return event
}

func spanKey(seg StreamSegment, entry chainEntry) string {
	return seg.StreamID + "\x00" + entry.config.ID
}

// charge adds one segment's time in an inspector to that inspector's own share
// of the stream. The guard measures the chain as a whole, and a chain-wide
// figure written onto every span is summed by the policy fold in
// pkg/app/metrics: with N streaming policies it would charge the hold N times
// and drive gateway_ms to zero, which is the miscount the stream span exists to
// avoid.
func (s *streamSpans) charge(seg StreamSegment, entry chainEntry, d time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.spent[spanKey(seg, entry)] += d
}

// markCut names the entry whose verdict stopped the stream. The guard knows a
// stream was cut but not by whom, and only the chain can tell: without this an
// observe-mode entry that cut nothing would publish the cut an enforce-mode
// entry beside it made.
func (s *streamSpans) markCut(seg StreamSegment, entry chainEntry) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cutBy[seg.StreamID] = spanKey(seg, entry)
}

// reporter names the entry asked to publish what describes the whole stream.
// The one that cut is preferred: the cut is what a per-response instrument is
// labelled by, and it is the only fact entryReport takes away from every entry
// but one. With nothing cut, chain order decides.
func (s *streamSpans) reporter(seg StreamSegment, entries []chainEntry) string {
	first := ""
	for _, entry := range entries {
		if _, ok := streamInspector(entry.plugin); !ok {
			continue
		}
		first = spanKey(seg, entry)
		break
	}
	if s == nil {
		return first
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cutter, ok := s.cutBy[seg.StreamID]; ok {
		return cutter
	}
	return first
}

// entryReport narrows the guard's chain-wide account to one entry. A cut no
// entry claimed — a transport failure resolved as fail_closed — is left on the
// entries that could have blocked, and never on the ones that only observe.
func (s *streamSpans) entryReport(seg StreamSegment, entry chainEntry) StreamReport {
	report := seg.Report
	if s == nil {
		return report
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := spanKey(seg, entry)
	report.GuardLatency = s.spent[key]
	cutter, claimed := s.cutBy[seg.StreamID]
	if (claimed && cutter != key) || (!claimed && !Blocks(entry.mode)) {
		report.CutAtEval = 0
		report.CutOffsetChars = 0
	}
	return report
}

func (s *streamSpans) publish() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, event := range s.events {
		event.Publish()
	}
}
