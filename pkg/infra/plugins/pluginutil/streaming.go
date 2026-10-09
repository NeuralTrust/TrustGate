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

package pluginutil

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

// Stream error policies: what the block loop does with held text when a
// per-block inspection call fails. A guardrail's availability failures (a
// provider outage, a timeout, rejected credentials) fail open, and the failures
// that depend on the content are the plugin's own to cut on
// (appplugins.ExternalStreamOutcome); a rewriter whose failure would release text
// it was meant to mask asks for fail_closed.
const (
	StreamOnErrorFailOpen   = "fail_open"
	StreamOnErrorFailClosed = "fail_closed"
)

// Settings keys a guardrail ignores. A guardrail's availability failures fail open,
// it takes the deployment-wide timeout, and a mask it cannot apply blocks in a
// mode that blocks, none of which a policy chooses, so a stored value for one of
// these would read as behaviour the policy does not have. Each guardrail returns
// the keys it carries from its RetiredSettings.
const (
	SettingOnError               = "on_error"
	SettingOnMaskFailure         = "on_mask_failure"
	SettingStreamingOnError      = "streaming.on_error"
	SettingStreamingGuardTimeout = "streaming.guard_timeout"
)

// The bounds are the engine's, not any one plugin's: they come from what the
// block loop and the detection backends can actually honour, so a plugin
// choosing its own defaults still validates against these.
const (
	minStreamHeadChars = 1
	maxStreamHeadChars = 4096

	minStreamMinCharsBetweenEvals = 256
	maxStreamMinCharsBetweenEvals = 65536

	minStreamMaxHoldMS = 50
	maxStreamMaxHoldMS = 5000

	minStreamMaxAccumulatedBytes = 4096
	// Detection backends stop inspecting above 1 MiB and say nothing about it,
	// so a payload larger than this is unguarded rather than merely expensive.
	maxStreamMaxAccumulatedBytes = 1048576
)

// StreamingSettings is the streaming block a plugin adds to its own settings
// schema to opt into per-block inspection of a streamed response leg. It is
// shared so that the same key means the same thing in every plugin that
// implements appplugins.StreamInspector, and so that an operator who has
// configured one has configured them all.
//
// There is deliberately no guard_timeout or on_error key: the per-block call runs
// under StreamingDefaults.GuardTimeout and a call that fails for the provider's
// availability fails open, so a policy cannot lengthen the wait on the stream or
// turn a provider outage into a cut. A
// plugin whose failure must stop the stream adds its own on_error beside this
// struct (regex_replace does).
//
// There is deliberately no max_inflight key: exactly one inspection call is in
// flight by construction, which is what makes each payload a contiguous prefix
// of the produced text.
type StreamingSettings struct {
	// Enabled is a pointer so an explicit false, the opt-out, is
	// distinguishable from an absent key. What an absent key means is the
	// plugin's call (StreamingDefaults.EnabledByDefault); read the resolved
	// value through IsEnabled, never by dereferencing this.
	Enabled              *bool `mapstructure:"enabled"`
	HeadChars            int   `mapstructure:"head_chars"`
	MinCharsBetweenEvals int   `mapstructure:"min_chars_between_evals"`
	MaxHoldMS            int   `mapstructure:"max_hold_ms"`
	MaxAccumulatedBytes  int   `mapstructure:"max_accumulated_bytes"`

	// defaultOn is what an absent Enabled means for the plugin that parsed
	// these settings. It is set by ApplyDefaults and never read from the
	// stored settings.
	defaultOn bool
}

// StreamingDefaults is what a plugin fills an absent key with. They are the
// plugin's own because what is a sensible block size depends on what the
// inspection costs: a local regex pass and a remote classifier do not want the
// same cadence.
type StreamingDefaults struct {
	// EnabledByDefault is what a policy that does not mention streaming.enabled
	// gets. An explicit enabled: false always wins over it.
	EnabledByDefault     bool
	HeadChars            int
	MinCharsBetweenEvals int
	MaxHoldMS            int
	MaxAccumulatedBytes  int
	GuardTimeout         time.Duration
}

// ApplyDefaults fills every absent key from d.
func (s *StreamingSettings) ApplyDefaults(d StreamingDefaults) {
	s.defaultOn = d.EnabledByDefault
	if s.HeadChars == 0 {
		s.HeadChars = d.HeadChars
	}
	if s.MinCharsBetweenEvals == 0 {
		s.MinCharsBetweenEvals = d.MinCharsBetweenEvals
	}
	if s.MaxHoldMS == 0 {
		s.MaxHoldMS = d.MaxHoldMS
	}
	if s.MaxAccumulatedBytes == 0 {
		s.MaxAccumulatedBytes = d.MaxAccumulatedBytes
	}
}

// Validate reports the first key that falls outside the engine's bounds,
// prefixed with plugin so the message names the policy the operator wrote.
// ApplyDefaults must have run first: a zero value here is a real zero, not an
// absent key.
func (s StreamingSettings) Validate(plugin string) error {
	if s.HeadChars < minStreamHeadChars || s.HeadChars > maxStreamHeadChars {
		return fmt.Errorf(
			"%s: streaming.head_chars must be between %d and %d, got %d",
			plugin, minStreamHeadChars, maxStreamHeadChars, s.HeadChars,
		)
	}
	if s.MinCharsBetweenEvals < minStreamMinCharsBetweenEvals ||
		s.MinCharsBetweenEvals > maxStreamMinCharsBetweenEvals {
		return fmt.Errorf(
			"%s: streaming.min_chars_between_evals must be between %d and %d, got %d",
			plugin, minStreamMinCharsBetweenEvals, maxStreamMinCharsBetweenEvals, s.MinCharsBetweenEvals,
		)
	}
	if s.MaxHoldMS < minStreamMaxHoldMS || s.MaxHoldMS > maxStreamMaxHoldMS {
		return fmt.Errorf(
			"%s: streaming.max_hold_ms must be between %d and %d, got %d",
			plugin, minStreamMaxHoldMS, maxStreamMaxHoldMS, s.MaxHoldMS,
		)
	}
	if s.MaxAccumulatedBytes < minStreamMaxAccumulatedBytes ||
		s.MaxAccumulatedBytes > maxStreamMaxAccumulatedBytes {
		return fmt.Errorf(
			"%s: streaming.max_accumulated_bytes must be between %d and %d, got %d",
			plugin, minStreamMaxAccumulatedBytes, maxStreamMaxAccumulatedBytes, s.MaxAccumulatedBytes,
		)
	}
	return nil
}

// IsEnabled reports whether a streamed response leg is inspected: the explicit
// setting when there is one, otherwise the plugin's default. ApplyDefaults must
// have run first, or an absent key reads as off.
func (s StreamingSettings) IsEnabled() bool {
	if s.Enabled != nil {
		return *s.Enabled
	}
	return s.defaultOn
}

// finalPassSettings decodes only streaming.final_pass. StreamingSettings has
// no such field because the block loop always inspects the end of a stream;
// ValidateFinalPassWrite reads it only to refuse an opt-out.
type finalPassSettings struct {
	Streaming struct {
		FinalPass *bool `mapstructure:"final_pass"`
	} `mapstructure:"streaming"`
}

// ValidateFinalPassWrite rejects a write that sets streaming.final_pass to
// false. The block loop inspects the end of every stream and has no way to
// release the tail unread, so a false would be stored and silently ignored
// (RUN-1745). A policy already stored with false stays editable while it
// keeps the value: it never changed what the stream did, and refusing it would
// block every later edit of that policy.
func ValidateFinalPassWrite(plugin string, settings, previous map[string]any) error {
	optOut, err := finalPassOptOut(settings)
	if err != nil {
		return fmt.Errorf("%s: %w", plugin, err)
	}
	if !optOut {
		return nil
	}
	if stored, err := finalPassOptOut(previous); err == nil && stored {
		return nil
	}
	return fmt.Errorf(
		"%s: streaming.final_pass cannot be false: the end of a streamed response is always inspected",
		plugin,
	)
}

func finalPassOptOut(settings map[string]any) (bool, error) {
	if settings == nil {
		return false, nil
	}
	cfg, err := Parse[finalPassSettings](settings)
	if err != nil {
		return false, err
	}
	return cfg.Streaming.FinalPass != nil && !*cfg.Streaming.FinalPass, nil
}

// StreamData is the per-stream aggregate one streamed response leg publishes,
// written once on the closing segment: Span.SetExtras overwrites rather than
// merges, so a per-block write would destroy the previous one.
//
// It is shared rather than declared per plugin because these keys land in
// ClickHouse and the console reads them by name. Two plugins emitting
// "guard_latency_ms_total" with different meanings, or one of them spelling it
// differently, is a data migration to undo rather than a code change.
//
// The fields carry no omitempty on purpose: once the block is present a zero is
// an answer ("no cut", "no degradation"), and dropping it would make the absent
// key ambiguous with a leg that never reported at all.
type StreamData struct {
	Enabled             bool   `json:"enabled"`
	StreamID            string `json:"stream_id"`
	EvalsTotal          int    `json:"evals_total"`
	CutAtEval           int    `json:"cut_at_eval"`
	CutOffsetChars      int    `json:"cut_offset_chars"`
	FinalPass           bool   `json:"final_pass"`
	GuardCalls          int    `json:"guard_calls"`
	GuardLatencyMsTotal int64  `json:"guard_latency_ms_total"`
	GuardLatencyMsMax   int64  `json:"guard_latency_ms_max"`
	AddedLatencyMs      int64  `json:"added_latency_ms"`
	// ChunkedBlocks counts the blocks larger than the entry's window that were
	// screened in chunks of it; it is omitted when there were none.
	ChunkedBlocks  int    `json:"chunked_blocks,omitempty"`
	DegradedReason string `json:"degraded_reason"`
	FallbackReason string `json:"fallback_reason"`
	// Findings is the one exception to the rule above: an absent key and an
	// empty list both say the stream reported nothing, so there is no zero to
	// preserve, and omitting it keeps a stream with no findings emitting the
	// event it emitted before the field existed.
	//
	// It holds fingerprints and never a finding's own fields, which are
	// free-form and can carry flagged response text.
	Findings []string `json:"findings,omitempty"`
}

// NewStreamData renders a guard report as the envelope a plugin publishes on
// the closing segment.
func NewStreamData(streamID string, r appplugins.StreamReport) *StreamData {
	return &StreamData{
		Enabled:             true,
		StreamID:            streamID,
		EvalsTotal:          r.Evals,
		CutAtEval:           r.CutAtEval,
		CutOffsetChars:      r.CutOffsetChars,
		FinalPass:           r.FinalPass,
		GuardCalls:          r.GuardCalls,
		GuardLatencyMsTotal: r.GuardLatency.Milliseconds(),
		GuardLatencyMsMax:   r.GuardLatencyMax.Milliseconds(),
		AddedLatencyMs:      r.AddedLatency.Milliseconds(),
		ChunkedBlocks:       r.ChunkedEvals,
		DegradedReason:      r.DegradedReason,
		FallbackReason:      r.FallbackReason,
	}
}

// fingerprintFieldSep joins identity fields before they are hashed, so that no
// field can be mistaken for part of the one beside it.
const fingerprintFieldSep = "\x00"

// fingerprintBytes is how much of the digest is kept. Half of SHA-256 is still
// 128 bits against a set holding a handful of entries per stream, and the
// string lands in an event rather than in a security decision.
const fingerprintBytes = 16

// StreamFingerprint digests what stays the same about a finding while the
// payload under it grows, so that alert-only reports one incident per stream
// instead of one per block.
//
// Callers pass identity only: who detected it and what it decided. A score is
// computed over the text the call carried, so on a longer prefix it comes back
// different and would turn the set into a counter of blocks. Flagged spans of
// the response are worse — hashing them would key the finding on content a
// transform is allowed to rewrite underneath it, and put a value derived from
// response text onto a span that publishes to OTLP.
//
// Fields that are all empty produce no fingerprint. An empty key would fold
// every unidentifiable finding in the stream into one, which is the opposite of
// what the set is for.
func StreamFingerprint(fields ...string) string {
	joined := strings.Join(fields, fingerprintFieldSep)
	if strings.TrimSpace(strings.ReplaceAll(joined, fingerprintFieldSep, "")) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(sum[:fingerprintBytes])
}

// DedupeFingerprints keeps the first occurrence of each key, in order, and
// drops the empties StreamFingerprint returns for a finding with no identity.
func DedupeFingerprints(prints []string) []string {
	if len(prints) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(prints))
	out := make([]string, 0, len(prints))
	for _, fp := range prints {
		if fp == "" {
			continue
		}
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, fp)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// StreamFingerprints is the fingerprint set a closing segment carries, without
// the chain entry the executor already narrowed it by: which entry a
// fingerprint belongs to is the span it is written on.
func StreamFingerprints(findings []appplugins.StreamFinding) []string {
	if len(findings) == 0 {
		return nil
	}
	prints := make([]string, 0, len(findings))
	for _, finding := range findings {
		prints = append(prints, finding.Fingerprint)
	}
	return prints
}

// Options is what StreamSettings hands back to the block loop. The knobs
// travel with the opt-in rather than being re-read by a caller that cannot
// parse the plugin's schema. A failed inspection call is released; a plugin that
// needs otherwise overrides OnError on the result, and one whose failure depends
// on the content cuts through appplugins.ExternalStreamOutcome.
func (s StreamingSettings) Options() appplugins.StreamOptions {
	return appplugins.StreamOptions{
		HeadChars:            s.HeadChars,
		OnError:              StreamOnErrorFailOpen,
		MinCharsBetweenEvals: s.MinCharsBetweenEvals,
		MaxHoldMS:            s.MaxHoldMS,
		MaxAccumulatedBytes:  s.MaxAccumulatedBytes,
	}
}

// OptionsWithin is Options with the window each evaluation may send capped at
// ceiling bytes, whatever max_accumulated_bytes asks for.
//
// Every block re-sends the tail of the accumulated text under a fixed per-block
// deadline, so a window that can grow with the stream makes the evaluation
// slower as the response gets longer: a client that opens with a long preamble
// would push the blocks that matter past the deadline, and an entry whose calls
// keep timing out is retired, leaving the rest of the stream uninspected. The
// ceiling is the size at which the provider still answers well inside the
// deadline, and the window always keeps the block's own new text plus the
// overlap with the previous blocks (the executor never cuts the block itself),
// so content that spans blocks is still seen.
func (s StreamingSettings) OptionsWithin(ceiling int) appplugins.StreamOptions {
	opts := s.Options()
	opts.MaxAccumulatedBytes = min(opts.MaxAccumulatedBytes, ceiling)
	return opts
}

// StreamFailedOpen reports whether the leg released text it could not inspect
// because this entry's own provider call failed, so the closing segment can say
// so instead of publishing "allowed" over it.
//
// The count is the executor's, per entry, and covers enforce and observe alike:
// in enforce the guard resolves the failure (the block is released), in observe
// the executor swallows it before the guard sees it. It is deliberately not read
// from DegradedReason, which is one value for the whole chain: it is copied to
// every entry, so a second policy with a good key would be labelled too, and a
// later size degrade overwrites it. Caller cancellation is not counted.
//
// A cut wins: the stream was stopped, which is a stronger fact than the earlier
// blocks that failed.
func StreamFailedOpen(r appplugins.StreamReport) bool {
	return r.CutAtEval == 0 && r.FailedEvals > 0
}

// StreamFailure is the reason and detail of the entry's first failed block, for
// the plugin to write on its Data in the one closing write. They are present
// whenever the entry failed during the stream, whatever the final decision.
func StreamFailure(r appplugins.StreamReport) (reason, detail string) {
	return string(r.FailureReason), r.FailureDetail
}

// StreamFailureClass is the class of the entry's first failed block, for the
// plugin to write as failure_class in the closing write. When the entry authored
// the cut it is the cutting failure's.
func StreamFailureClass(r appplugins.StreamReport) string {
	return string(r.FailureClass)
}

// StreamCutDecision is the decision an entry records for the cut it authored. A
// cut that is a finding is the plugin's own blocked token. A cut that is an
// input failure is failed_closed: the guardrail could not read the content, and
// there is no finding to name. A mask over a confirmed finding that could not be
// applied stays blocked (with the plugin marking it degraded), because a
// finding exists and a failed_closed would hide it.
func StreamCutDecision(r appplugins.StreamReport, blocked string) string {
	if r.CutOnFailure && !appplugins.IsMaskOverFinding(r.FailureDetail) {
		return appplugins.DecisionFailedClosed
	}
	return blocked
}
