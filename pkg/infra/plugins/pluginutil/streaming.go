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

// Stream error policies. They bound the per-block inspection call only, so a
// plugin's buffered legs keep whatever the policy's own on_error says.
const (
	StreamOnErrorFailOpen   = "fail_open"
	StreamOnErrorFailClosed = "fail_closed"
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

	minStreamGuardTimeout = 250 * time.Millisecond
	maxStreamGuardTimeout = 10 * time.Second
)

// StreamingSettings is the streaming block a plugin adds to its own settings
// schema to opt into per-block inspection of a streamed response leg. It is
// shared so that the same key means the same thing in every plugin that
// implements appplugins.StreamInspector, and so that an operator who has
// configured one has configured them all.
//
// There is deliberately no max_inflight key: exactly one inspection call is in
// flight by construction, which is what makes each payload a contiguous prefix
// of the produced text.
type StreamingSettings struct {
	Enabled              bool `mapstructure:"enabled"`
	HeadChars            int  `mapstructure:"head_chars"`
	MinCharsBetweenEvals int  `mapstructure:"min_chars_between_evals"`
	MaxHoldMS            int  `mapstructure:"max_hold_ms"`
	MaxAccumulatedBytes  int  `mapstructure:"max_accumulated_bytes"`
	// FinalPass is a pointer so that an explicit false is distinguishable from
	// an absent key, which defaults to true.
	FinalPass    *bool  `mapstructure:"final_pass"`
	GuardTimeout string `mapstructure:"guard_timeout"`
	// OnError bounds the per-block call only. It inherits the policy's own
	// on_error when unset, so the stream leg cannot be made stricter or laxer
	// than the rest of the plugin by accident.
	OnError string `mapstructure:"on_error"`
}

// StreamingDefaults is what a plugin fills an absent key with. They are the
// plugin's own because what is a sensible block size depends on what the
// inspection costs: a local regex pass and a remote classifier do not want the
// same cadence.
type StreamingDefaults struct {
	HeadChars            int
	MinCharsBetweenEvals int
	MaxHoldMS            int
	MaxAccumulatedBytes  int
	GuardTimeout         time.Duration
}

// ApplyDefaults fills every absent key from d, and inherits onError for the
// stream leg when the block does not override it.
func (s *StreamingSettings) ApplyDefaults(d StreamingDefaults, onError string) {
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
	s.GuardTimeout = strings.TrimSpace(s.GuardTimeout)
	if s.GuardTimeout == "" {
		s.GuardTimeout = d.GuardTimeout.String()
	}
	if s.OnError == "" {
		s.OnError = onError
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
	d, err := time.ParseDuration(s.GuardTimeout)
	if err != nil {
		return fmt.Errorf("%s: streaming.guard_timeout must be a duration such as 2s: %w", plugin, err)
	}
	if d < minStreamGuardTimeout || d > maxStreamGuardTimeout {
		return fmt.Errorf(
			"%s: streaming.guard_timeout must be between %s and %s, got %s",
			plugin, minStreamGuardTimeout, maxStreamGuardTimeout, d,
		)
	}
	switch s.OnError {
	case StreamOnErrorFailOpen, StreamOnErrorFailClosed:
	default:
		return fmt.Errorf("%s: streaming.on_error must be one of fail_open, fail_closed", plugin)
	}
	return nil
}

// FinalPassEnabled reports whether the block carrying the end of the stream is
// inspected. An absent key enables it.
func (s StreamingSettings) FinalPassEnabled() bool {
	return s.FinalPass == nil || *s.FinalPass
}

// Timeout is the parsed guard_timeout, falling back to d when the value cannot
// be parsed. Validate rejects such a value, so the fallback only covers a
// caller that reads the settings without validating them.
func (s StreamingSettings) Timeout(d time.Duration) time.Duration {
	parsed, err := time.ParseDuration(s.GuardTimeout)
	if err != nil {
		return d
	}
	return parsed
}

// FailClosed reports whether a failed inspection call stops the stream.
func (s StreamingSettings) FailClosed() bool {
	return s.OnError == StreamOnErrorFailClosed
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
	DegradedReason      string `json:"degraded_reason"`
	FallbackReason      string `json:"fallback_reason"`
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
// parse the plugin's schema, so an operator who asked for fail_closed does not
// silently get fail_open.
func (s StreamingSettings) Options() appplugins.StreamOptions {
	return appplugins.StreamOptions{
		HeadChars:            s.HeadChars,
		OnError:              s.OnError,
		MinCharsBetweenEvals: s.MinCharsBetweenEvals,
		MaxHoldMS:            s.MaxHoldMS,
		MaxAccumulatedBytes:  s.MaxAccumulatedBytes,
	}
}
