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
	"errors"
	"slices"
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
// deltas. Truncated says Accumulated is a tail window rather than a full
// prefix, because the guard hit its accumulation cap or the entry's own
// max_accumulated_bytes is smaller, so the plugin can carry the distinction
// onto the wire envelope the engine reads.
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
	// Findings is every fingerprint the chain returned over the stream, in
	// first-seen order with the repeats collapsed, filled on the closing
	// segment and empty on every other. The guard folds one set for the whole
	// chain and the executor narrows it to the entry being called, the way it
	// narrows Report: an inspector is handed what it reported and nothing a
	// second policy on the same stream reported.
	//
	// The set lives with the guard rather than with an inspector because an
	// inspector is a process-wide singleton called once per block: a set it
	// kept itself would have to be keyed on the stream and swept afterwards,
	// and a sweep missed on any of the paths a stream can end on is an
	// unbounded map. The guard's own state is freed with the stream on every
	// one of them.
	Findings []StreamFinding
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
// the cut fields are cleared on every entry but the one that authored the cut.
// The rest — Evals, GuardCalls, GuardLatencyMax, AddedLatency, FinalPass and
// the two reasons — describe the stream, not the entry, and reach every entry
// unchanged.
type StreamReport struct {
	Evals           int
	GuardCalls      int
	GuardLatency    time.Duration
	GuardLatencyMax time.Duration
	AddedLatency    time.Duration
	CutAtEval       int
	CutOffsetChars  int
	// CutOnFailure says the cut resolved a failed call as fail_closed. Its
	// author is the entry whose call failed, not the maskers of that block,
	// whose mask the guard never got to apply (RUN-1745 F6).
	CutOnFailure bool
	// MaskedEvals counts the blocks on which this entry's enforced mask went
	// into the one handed to the guard. Only the executor knows it, so it is
	// zero on the guard's chain-wide report and set per entry. With no cut,
	// the guard applied every one of them: it applies a mask or cuts.
	MaskedEvals int
	// FailedEvals counts the blocks on which this entry's own call failed and
	// the held text was released (or the stream was cut) without its verdict.
	// Like MaskedEvals only the executor knows it, so it is zero on the guard's
	// chain-wide report and set per entry. DegradedReason cannot say this: it is
	// one value for the whole chain, and a later size degrade overwrites it.
	FailedEvals int
	// FailureReason and FailureDetail are the FIRST failure this entry had on
	// the stream, as the typed error its plugin returned carried them
	// (ExternalStreamFailure). Like FailedEvals only the executor knows them,
	// per entry; they are empty for an entry that did not fail and for a
	// failure whose error was not an ExternalStreamFailure. They are kept
	// whatever the final decision was: a cut, a finding or a mask does not
	// erase that an earlier block went uninspected.
	FailureReason  FailureReason
	FailureDetail  string
	FinalPass      bool
	DegradedReason string
	FallbackReason string
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
	StreamDegradeAccumulationCap = "accumulation_cap"
	StreamDegradeGuardTimeout    = "guard_timeout"
	StreamDegradeGuardError      = "guard_error"
	// StreamDegradeToolInputUninspected says a native tool call was released
	// without its input having been read as a text of its own: it outgrew the hold,
	// the stream ended before it closed, or its format is not understood.
	StreamDegradeToolInputUninspected = "tool_input_uninspected"
	StreamFallbackSegmentationUnavail = "segmentation_unavailable"
	StreamFallbackClientDisconnected  = "client_disconnected"
	// StreamFallbackEntryRetired is published on ONE entry's span: its provider
	// failed on streamEntryRetireAfter blocks in a row and the executor stopped
	// calling it for the rest of the stream. The other entries keep inspecting,
	// which is why this is the entry's own reason and not the guard's.
	StreamFallbackEntryRetired = "entry_retired"
)

// SegmentVerdict is a plugin's answer for one StreamSegment. Transformed, when
// HasTransform is set, replaces the whole of StreamSegment.Accumulated: the
// caller owns a single contiguous buffer and rewrites it in place, so splicing
// per-segment fragments back together is never required.
//
// Fingerprints digests what the plugin reported on this segment down to what
// stays the same about a finding while the payload under it grows. A plugin
// returns its own and nothing else: the executor tags each one with the entry
// it called, so which policy a fingerprint belongs to is never something an
// inspector encodes into the value.
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

// StreamOptionsOwner is the optional declaration of a StreamInspector that is a
// passive participant: it rewrites or reads blocks but must not set the
// stream-wide options. One stream carries one head gate, one cadence and one
// failure direction, so whichever entry owns them decides how every other
// participant's stream behaves. A local rewriter that owned them would flip a
// third-party guardrail's chosen on_error and cadence just by sorting first.
//
// An inspector that does not implement it owns its options.
type StreamOptionsOwner interface {
	OwnsStreamOptions() bool
}

func ownsStreamOptions(d PluginDescriptor) bool {
	if o, ok := d.(StreamOptionsOwner); ok {
		return o.OwnsStreamOptions()
	}
	return true
}

// SegmentOutcome is the executor's consolidated answer across the chain for one
// StreamSegment. Fingerprints carries what every entry reported on the segment,
// each tagged with the entry that reported it.
type SegmentOutcome struct {
	// FailedEntries counts the entries that gave no verdict on this block
	// because their own call failed (and was absorbed per entry) or because
	// they were retired. The guard cannot see an absorbed failure, so this is
	// how GuardCalls stays the number of blocks that got every verdict.
	FailedEntries int
	// WindowedEntries counts the entries that were handed only the tail of
	// Accumulated because their own streaming.max_accumulated_bytes is smaller
	// than the text produced. The guard's own Truncated flag cannot see this: the
	// narrowing happens per entry, on a copy. An entry that saw a tail never
	// evaluated the whole response.
	WindowedEntries int
	Block           bool
	Type            string
	Message         string
	HasTransform    bool
	Transformed     string
	Fingerprints    []StreamFinding
}

// StreamFinding is one finding fingerprint and the chain entry that reported
// it. The guard folds a single set for the whole stream, so an untagged
// fingerprint would leave two policies inspecting the same stream each
// publishing the other's findings. Attribution is the executor's to record: it
// knows the chain, and it narrows the set back to one entry before an inspector
// is handed it.
type StreamFinding struct {
	Entry       string
	Fingerprint string
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
	mu       sync.Mutex
	events   map[string]*metrics.EventContext
	spent    map[string]time.Duration
	cutBy    map[string][]string
	failedBy map[string]string
	masked   map[string]int
	// failed counts, per entry, the blocks on which its own call failed and
	// the failure was not the caller's cancellation. It is per entry because
	// the guard's DegradedReason is one value for the whole chain: it is copied
	// to every entry and the last degrade overwrites it.
	failed map[string]int
	// failureReason and failureDetail hold, per entry, what the first failure
	// that carries a reason (a typed ExternalStreamFailure) said. Later ones
	// never overwrite them: the first is the cause, and the ones behind it are
	// usually the same outage repeating. A failure with no reason is not
	// tracked, so a typed one behind it is the first recorded.
	failureReason map[string]FailureReason
	failureDetail map[string]string
	// streak counts the consecutive absorbed failures of an entry and retired
	// records the ones that reached streamEntryRetireAfter. A streak ends on a
	// call that returns.
	streak  map[string]int
	retired map[string]bool
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
		events:   make(map[string]*metrics.EventContext),
		spent:    make(map[string]time.Duration),
		cutBy:    make(map[string][]string),
		failedBy: make(map[string]string),
		masked:   make(map[string]int),
		failed:   make(map[string]int),

		failureReason: make(map[string]FailureReason),
		failureDetail: make(map[string]string),
		streak:        make(map[string]int),
		retired:       make(map[string]bool),
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

// streamEntryRetireAfter is how many blocks in a row an entry may fail, absorbed
// per entry, before it is no longer called for the rest of the stream. Absorbing
// hides the failure from the guard, which retires the whole block loop after
// maxConsecutiveFailures; without this a hung provider would stall every block
// of every stream for its own timeout. Only the failing entry is retired:
// retiring the loop would blind the healthy policies beside it.
const streamEntryRetireAfter = 3

// handedBack records a failure the executor handed to the guard: it counts for
// FailedEvals and nothing else. Retirement is only ever for absorbed failures,
// whose error the guard never sees; a handed-back one is the guard's to resolve
// (and to retire the loop on, after maxConsecutiveFailures).
func (s *streamSpans) handedBack(key string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed[key]++
}

// fail records that this entry's own call failed on a block and was absorbed,
// and reports whether it was the first failure of the stream and whether it has
// now reached the retirement streak.
func (s *streamSpans) fail(key string) (first, retiredNow bool) {
	if s == nil {
		return false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed[key]++
	s.streak[key]++
	if s.streak[key] >= streamEntryRetireAfter && !s.retired[key] {
		s.retired[key] = true
		retiredNow = true
	}
	return s.failed[key] == 1, retiredNow
}

// noteFailure keeps the reason and detail of an entry's first typed failure
// (the first failure that carries a reason) on the stream. An error that is not an ExternalStreamFailure (a plugin that
// does not use the shared vocabulary) records nothing, and the error text is
// never parsed to guess one.
func (s *streamSpans) noteFailure(key string, err error) {
	if s == nil {
		return
	}
	var failure *ExternalStreamFailure
	if !errors.As(err, &failure) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.failureReason[key]; seen {
		return
	}
	s.failureReason[key] = failure.Reason
	s.failureDetail[key] = failure.Detail
}

// closingFailure gives an entry whose closing segment itself failed the
// decision its plugin could not write, so the span does not end with none.
// failsOpen is the entry's own answer (observe, or streaming.on_error
// fail_open): it records failed_open. Otherwise the stream's on_error decided
// for it, and the guard's answer is in the report it was handed: a cut it
// resolved on this entry's failed call is failed_closed, anything else is a
// release, so failed_open. The guard's on_error is not visible from here, so a
// failure the report does not attribute to this entry is recorded failed_open
// rather than guessed at.
//
// Precondition: this runs only when the plugin's closing call returned an
// error, which a plugin does before its one extras write. SetExtras replaces
// and SetDecision overwrites, so writing over a plugin's own account would
// destroy it: the extras write is skipped when the span already carries any.
// The decision is still set, because an absorbed block failure may already have
// recorded failed_open there and the closing answer supersedes it. When a typed
// failure is known and no extras exist, its reason and detail are written as
// the entry's extras, the only way the closing write that was owed them still
// reaches the event.
func (s *streamSpans) closingFailure(event *metrics.EventContext, key string, err error, report StreamReport, failsOpen bool) {
	if event == nil {
		return
	}
	decision := DecisionFailedOpen
	if !failsOpen && report.CutOnFailure && report.FailedEvals > 0 {
		decision = DecisionFailedClosed
	}
	SetDecisionFromOutcome(event, decision)
	s.noteFailure(key, err)
	if s == nil {
		return
	}
	s.mu.Lock()
	reason, detail := s.failureReason[key], s.failureDetail[key]
	s.mu.Unlock()
	if reason == "" || event.HasExtras() {
		return
	}
	extras := map[string]any{"decision": decision, "failure_reason": string(reason)}
	if detail != "" {
		extras["failure_detail"] = detail
	}
	event.SetExtras(extras)
}

// recovered ends an entry's streak: a call that returned.
func (s *streamSpans) recovered(key string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.streak, key)
}

func (s *streamSpans) isRetired(key string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retired[key]
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
	span.SetStreamed()
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

// setCut records which entries author the cut on the segment just evaluated,
// replacing whatever an earlier segment stored. The guard knows a stream was
// cut but not by whom, and only the chain can tell: without this an
// observe-mode entry that cut nothing would publish the cut an enforce-mode
// entry beside it made. A block names one entry; a transform names every entry
// whose mask went into the one that could not be applied. failed names the
// enforcing entry whose call failed on the segment, the author of the cut when
// the guard resolves that failure as fail_closed. masks says the keys' masks
// were handed to the guard, which counts them per entry (MaskedEvals).
func (s *streamSpans) setCut(seg StreamSegment, keys []string, failed string, masks bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if masks {
		for _, key := range keys {
			s.masked[key]++
		}
	}
	if failed == "" {
		delete(s.failedBy, seg.StreamID)
	} else {
		s.failedBy[seg.StreamID] = failed
	}
	if len(keys) == 0 {
		delete(s.cutBy, seg.StreamID)
		return
	}
	s.cutBy[seg.StreamID] = append([]string(nil), keys...)
}

// cutAuthorsLocked names the entries that authored the stream's cut. A cut
// that resolved a failed call as fail_closed belongs to the entry whose call
// failed: blaming the maskers of that block, as the verdict list alone would,
// reported a cut against a policy that masked and none against the one that
// failed (RUN-1745 F6). Every other cut belongs to the verdicts setCut kept.
// The caller holds s.mu.
func (s *streamSpans) cutAuthorsLocked(seg StreamSegment) []string {
	if seg.Report.CutOnFailure {
		if failed := s.failedBy[seg.StreamID]; failed != "" {
			return []string{failed}
		}
	}
	return s.cutBy[seg.StreamID]
}

// reporters names, for each plugin on the chain, the one entry asked to
// publish what describes the whole stream. The instruments an inspector records
// for a response are its own (trustguard_stream_*), so one entry per plugin
// records them: two policies of one plugin would count the response twice, and
// a single reporter for the whole chain left every other plugin's instruments
// unwritten whenever it was not that plugin's entry (RUN-1745 F5). Within a
// plugin the entry that cut is preferred: the cut is what a per-response
// instrument is labelled by, and it is the only fact entryReport takes away
// from every entry but the cutter. With nothing cut, chain order decides.
func (s *streamSpans) reporters(seg StreamSegment, entries []chainEntry) map[string]bool {
	var cutters []string
	if s != nil {
		s.mu.Lock()
		cutters = append(cutters, s.cutAuthorsLocked(seg)...)
		s.mu.Unlock()
	}
	chosen := make(map[string]string, len(entries))
	for _, entry := range entries {
		key := spanKey(seg, entry)
		if _, done := chosen[entry.plugin.Name()]; !done && slices.Contains(cutters, key) {
			chosen[entry.plugin.Name()] = key
		}
	}
	for _, entry := range entries {
		if _, ok := streamInspector(entry.plugin); !ok {
			continue
		}
		if _, done := chosen[entry.plugin.Name()]; !done {
			chosen[entry.plugin.Name()] = spanKey(seg, entry)
		}
	}
	out := make(map[string]bool, len(chosen))
	for _, key := range chosen {
		out[key] = true
	}
	return out
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
	report.MaskedEvals = s.masked[key]
	report.FailedEvals = s.failed[key]
	report.FailureReason = s.failureReason[key]
	report.FailureDetail = s.failureDetail[key]
	if s.retired[key] && report.FallbackReason == "" {
		report.FallbackReason = StreamFallbackEntryRetired
	}
	cutters := s.cutAuthorsLocked(seg)
	claimed := len(cutters) > 0
	claimedByEntry := false
	for _, k := range cutters {
		claimedByEntry = claimedByEntry || k == key
	}
	if (claimed && !claimedByEntry) || (!claimed && !Blocks(entry.mode)) {
		report.CutAtEval = 0
		report.CutOffsetChars = 0
	}
	// CutOnFailure travels with the cut: it says THIS entry's failed call was
	// resolved as fail_closed, so an entry that did not author the cut (it
	// masked, observed, or failed open earlier) must not read it as its own.
	if report.CutAtEval == 0 {
		report.CutOnFailure = false
	}
	return report
}

// entryFindings narrows the stream's set to what this entry reported. An entry
// publishes its own findings or none, for the same reason entryReport hands it
// its own share of the chain's latency: the set is folded once for a chain that
// several policies can sit in.
func entryFindings(findings []StreamFinding, entry chainEntry) []StreamFinding {
	mine := make([]StreamFinding, 0, len(findings))
	for _, finding := range findings {
		if finding.Entry != entry.config.ID {
			continue
		}
		mine = append(mine, finding)
	}
	if len(mine) == 0 {
		return nil
	}
	return mine
}

func (s *streamSpans) publish() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, event := range s.events {
		// The inspector sets this itself on the closing segment; the fallback
		// covers the one that failed before it could. Without it the span would
		// end on its wall clock — the whole drain — and pkg/app/metrics would
		// deduct that from provider_ms as if the guard had held every byte.
		event.SetSLatencyDefault(s.spent[key])
		event.Publish()
	}
}
