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
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

func testDefaults() StreamingDefaults {
	return StreamingDefaults{
		HeadChars:            400,
		MinCharsBetweenEvals: 2048,
		MaxHoldMS:            800,
		MaxAccumulatedBytes:  262144,
		GuardTimeout:         2 * time.Second,
	}
}

func validSettings() StreamingSettings {
	s := StreamingSettings{Enabled: true}
	s.ApplyDefaults(testDefaults(), StreamOnErrorFailOpen)
	return s
}

func TestApplyDefaultsFillsAbsentKeys(t *testing.T) {
	t.Parallel()
	var s StreamingSettings
	s.ApplyDefaults(testDefaults(), StreamOnErrorFailClosed)

	if s.HeadChars != 400 {
		t.Errorf("HeadChars = %d, want 400", s.HeadChars)
	}
	if s.MinCharsBetweenEvals != 2048 {
		t.Errorf("MinCharsBetweenEvals = %d, want 2048", s.MinCharsBetweenEvals)
	}
	if s.MaxHoldMS != 800 {
		t.Errorf("MaxHoldMS = %d, want 800", s.MaxHoldMS)
	}
	if s.MaxAccumulatedBytes != 262144 {
		t.Errorf("MaxAccumulatedBytes = %d, want 262144", s.MaxAccumulatedBytes)
	}
	if s.GuardTimeout != "2s" {
		t.Errorf("GuardTimeout = %q, want %q", s.GuardTimeout, "2s")
	}
	if s.OnError != StreamOnErrorFailClosed {
		t.Errorf("OnError = %q, want inherited %q", s.OnError, StreamOnErrorFailClosed)
	}
}

func TestApplyDefaultsKeepsExplicitValues(t *testing.T) {
	t.Parallel()
	explicitFalse := false
	s := StreamingSettings{
		HeadChars:            10,
		MinCharsBetweenEvals: 300,
		MaxHoldMS:            60,
		MaxAccumulatedBytes:  8192,
		FinalPass:            &explicitFalse,
		GuardTimeout:         "  1500ms  ",
		OnError:              StreamOnErrorFailClosed,
	}
	s.ApplyDefaults(testDefaults(), StreamOnErrorFailOpen)

	if s.HeadChars != 10 || s.MinCharsBetweenEvals != 300 || s.MaxHoldMS != 60 ||
		s.MaxAccumulatedBytes != 8192 {
		t.Fatalf("defaults overwrote explicit numbers: %+v", s)
	}
	if s.GuardTimeout != "1500ms" {
		t.Errorf("GuardTimeout = %q, want the trimmed explicit value", s.GuardTimeout)
	}
	if s.OnError != StreamOnErrorFailClosed {
		t.Errorf("OnError = %q, want the explicit value to survive inheritance", s.OnError)
	}
	if s.FinalPassEnabled() {
		t.Error("FinalPassEnabled() = true, want an explicit false to be honoured")
	}
}

func TestFinalPassDefaultsToEnabled(t *testing.T) {
	t.Parallel()
	if !(StreamingSettings{}).FinalPassEnabled() {
		t.Error("an absent final_pass must enable the final block")
	}
	enabled := true
	if !(StreamingSettings{FinalPass: &enabled}).FinalPassEnabled() {
		t.Error("an explicit true must enable the final block")
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	t.Parallel()
	if err := validSettings().Validate("acme"); err != nil {
		t.Fatalf("defaults must validate, got %v", err)
	}
}

func TestValidateRejectsOutOfBounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(*StreamingSettings)
		wantKey string
	}{
		{"head_chars below min", func(s *StreamingSettings) { s.HeadChars = 0 }, "streaming.head_chars"},
		{"head_chars above max", func(s *StreamingSettings) { s.HeadChars = 4097 }, "streaming.head_chars"},
		{"min_chars below min", func(s *StreamingSettings) { s.MinCharsBetweenEvals = 255 }, "streaming.min_chars_between_evals"},
		{"min_chars above max", func(s *StreamingSettings) { s.MinCharsBetweenEvals = 65537 }, "streaming.min_chars_between_evals"},
		{"max_hold below min", func(s *StreamingSettings) { s.MaxHoldMS = 49 }, "streaming.max_hold_ms"},
		{"max_hold above max", func(s *StreamingSettings) { s.MaxHoldMS = 5001 }, "streaming.max_hold_ms"},
		{"accumulated below min", func(s *StreamingSettings) { s.MaxAccumulatedBytes = 4095 }, "streaming.max_accumulated_bytes"},
		{"accumulated above max", func(s *StreamingSettings) { s.MaxAccumulatedBytes = 1048577 }, "streaming.max_accumulated_bytes"},
		{"timeout below min", func(s *StreamingSettings) { s.GuardTimeout = "249ms" }, "streaming.guard_timeout"},
		{"timeout above max", func(s *StreamingSettings) { s.GuardTimeout = "11s" }, "streaming.guard_timeout"},
		{"timeout unparseable", func(s *StreamingSettings) { s.GuardTimeout = "soon" }, "streaming.guard_timeout"},
		{"unknown on_error", func(s *StreamingSettings) { s.OnError = "fail_sideways" }, "streaming.on_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := validSettings()
			tc.mutate(&s)
			err := s.Validate("acme")
			if err == nil {
				t.Fatalf("expected %s to be rejected", tc.wantKey)
			}
			if !strings.Contains(err.Error(), tc.wantKey) {
				t.Errorf("error %q does not name %s", err, tc.wantKey)
			}
			if !strings.HasPrefix(err.Error(), "acme: ") {
				t.Errorf("error %q is not prefixed with the plugin name", err)
			}
		})
	}
}

func TestValidateAcceptsBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*StreamingSettings)
	}{
		{"head_chars at min", func(s *StreamingSettings) { s.HeadChars = 1 }},
		{"head_chars at max", func(s *StreamingSettings) { s.HeadChars = 4096 }},
		{"min_chars at min", func(s *StreamingSettings) { s.MinCharsBetweenEvals = 256 }},
		{"min_chars at max", func(s *StreamingSettings) { s.MinCharsBetweenEvals = 65536 }},
		{"max_hold at min", func(s *StreamingSettings) { s.MaxHoldMS = 50 }},
		{"max_hold at max", func(s *StreamingSettings) { s.MaxHoldMS = 5000 }},
		{"accumulated at min", func(s *StreamingSettings) { s.MaxAccumulatedBytes = 4096 }},
		{"accumulated at max", func(s *StreamingSettings) { s.MaxAccumulatedBytes = 1048576 }},
		{"timeout at min", func(s *StreamingSettings) { s.GuardTimeout = "250ms" }},
		{"timeout at max", func(s *StreamingSettings) { s.GuardTimeout = "10s" }},
		{"on_error fail_closed", func(s *StreamingSettings) { s.OnError = StreamOnErrorFailClosed }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := validSettings()
			tc.mutate(&s)
			if err := s.Validate("acme"); err != nil {
				t.Fatalf("boundary must be accepted, got %v", err)
			}
		})
	}
}

func TestTimeoutFallsBackOnUnparseableValue(t *testing.T) {
	t.Parallel()
	s := StreamingSettings{GuardTimeout: "3s"}
	if got := s.Timeout(time.Second); got != 3*time.Second {
		t.Errorf("Timeout() = %s, want 3s", got)
	}
	s.GuardTimeout = "whenever"
	if got := s.Timeout(time.Second); got != time.Second {
		t.Errorf("Timeout() = %s, want the fallback 1s", got)
	}
}

func TestFailClosed(t *testing.T) {
	t.Parallel()
	if (StreamingSettings{OnError: StreamOnErrorFailClosed}).FailClosed() != true {
		t.Error("fail_closed must report FailClosed")
	}
	if (StreamingSettings{OnError: StreamOnErrorFailOpen}).FailClosed() != false {
		t.Error("fail_open must not report FailClosed")
	}
	if (StreamingSettings{}).FailClosed() != false {
		t.Error("an unset on_error must not report FailClosed")
	}
}

func TestOptionsCarriesEveryKnob(t *testing.T) {
	t.Parallel()
	s := StreamingSettings{
		HeadChars:            11,
		MinCharsBetweenEvals: 22,
		MaxHoldMS:            33,
		MaxAccumulatedBytes:  44,
		OnError:              StreamOnErrorFailClosed,
	}
	got := s.Options()
	if got.HeadChars != 11 {
		t.Errorf("HeadChars = %d, want 11", got.HeadChars)
	}
	if got.MinCharsBetweenEvals != 22 {
		t.Errorf("MinCharsBetweenEvals = %d, want 22", got.MinCharsBetweenEvals)
	}
	if got.MaxHoldMS != 33 {
		t.Errorf("MaxHoldMS = %d, want 33", got.MaxHoldMS)
	}
	if got.MaxAccumulatedBytes != 44 {
		t.Errorf("MaxAccumulatedBytes = %d, want 44", got.MaxAccumulatedBytes)
	}
	if got.OnError != StreamOnErrorFailClosed {
		t.Errorf("OnError = %q, want %q", got.OnError, StreamOnErrorFailClosed)
	}
}

func TestNewStreamDataRendersTheReport(t *testing.T) {
	t.Parallel()
	got := NewStreamData("trace-1:response", appplugins.StreamReport{
		Evals:           6,
		GuardCalls:      5,
		GuardLatency:    1500 * time.Millisecond,
		GuardLatencyMax: 400 * time.Millisecond,
		AddedLatency:    900 * time.Millisecond,
		CutAtEval:       3,
		CutOffsetChars:  438,
		FinalPass:       true,
		DegradedReason:  appplugins.StreamDegradeGuardTimeout,
		FallbackReason:  appplugins.StreamFallbackClientDisconnected,
	})

	if !got.Enabled {
		t.Error("Enabled must be set on a published envelope")
	}
	if got.StreamID != "trace-1:response" {
		t.Errorf("StreamID = %q", got.StreamID)
	}
	if got.EvalsTotal != 6 || got.GuardCalls != 5 {
		t.Errorf("counters = %d/%d, want 6/5", got.EvalsTotal, got.GuardCalls)
	}
	if got.GuardLatencyMsTotal != 1500 || got.GuardLatencyMsMax != 400 || got.AddedLatencyMs != 900 {
		t.Errorf("latencies = %d/%d/%d, want 1500/400/900",
			got.GuardLatencyMsTotal, got.GuardLatencyMsMax, got.AddedLatencyMs)
	}
	if got.CutAtEval != 3 || got.CutOffsetChars != 438 {
		t.Errorf("cut = %d@%d, want 3@438", got.CutAtEval, got.CutOffsetChars)
	}
	if !got.FinalPass {
		t.Error("FinalPass did not carry")
	}
	if got.DegradedReason != appplugins.StreamDegradeGuardTimeout ||
		got.FallbackReason != appplugins.StreamFallbackClientDisconnected {
		t.Errorf("reasons = %q/%q", got.DegradedReason, got.FallbackReason)
	}
}

// The console reads these keys by name out of ClickHouse, so renaming one after
// release is a data migration. The literal list is the point of the test.
func TestStreamDataKeysAreStable(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(NewStreamData("id", appplugins.StreamReport{}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{
		"added_latency_ms", "cut_at_eval", "cut_offset_chars", "degraded_reason",
		"enabled", "evals_total", "fallback_reason", "final_pass", "guard_calls",
		"guard_latency_ms_max", "guard_latency_ms_total", "stream_id",
	}
	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("key %q is missing from the published envelope", key)
		}
	}
	if len(got) != len(want) {
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Errorf("envelope has %d keys, want %d: %v", len(got), len(want), keys)
	}
	if _, ok := got["findings"]; ok {
		t.Error("findings must be omitted when the stream reported none")
	}
}

func TestStreamFingerprintIsStableAndFieldSensitive(t *testing.T) {
	t.Parallel()
	base := StreamFingerprint("plug", "hate", "threshold")
	if base == "" {
		t.Fatal("identified fields must produce a key")
	}
	if base != StreamFingerprint("plug", "hate", "threshold") {
		t.Error("the same identity must produce the same key")
	}
	if base == StreamFingerprint("plug", "hate", "flagged") {
		t.Error("a different rule must produce a different key")
	}
	if base == StreamFingerprint("plug", "violence", "threshold") {
		t.Error("a different category must produce a different key")
	}
	if len(base) != fingerprintBytes*2 {
		t.Errorf("key length = %d, want %d hex chars", len(base), fingerprintBytes*2)
	}
}

// Joining on a separator that cannot occur in a field is what stops two
// different identities colliding by concatenation.
func TestStreamFingerprintSeparatesFields(t *testing.T) {
	t.Parallel()
	if StreamFingerprint("ab", "c") == StreamFingerprint("a", "bc") {
		t.Error("field boundaries must survive hashing")
	}
}

func TestStreamFingerprintRejectsAnEmptyIdentity(t *testing.T) {
	t.Parallel()
	for _, fields := range [][]string{nil, {""}, {"", ""}, {"  ", "\t"}} {
		if got := StreamFingerprint(fields...); got != "" {
			t.Errorf("StreamFingerprint(%q) = %q, want an empty key", fields, got)
		}
	}
}

func TestDedupeFingerprintsKeepsFirstOccurrenceInOrder(t *testing.T) {
	t.Parallel()
	got := DedupeFingerprints([]string{"b", "a", "", "b", "c", "a"})
	want := []string{"b", "a", "c"}
	if len(got) != len(want) {
		t.Fatalf("DedupeFingerprints() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("DedupeFingerprints() = %v, want %v", got, want)
		}
	}
	if got := DedupeFingerprints(nil); got != nil {
		t.Errorf("DedupeFingerprints(nil) = %v, want nil", got)
	}
	if got := DedupeFingerprints([]string{"", ""}); got != nil {
		t.Errorf("a set of unidentified findings must collapse to nil, got %v", got)
	}
}

func TestStreamFingerprintsDropsTheEntryTag(t *testing.T) {
	t.Parallel()
	if got := StreamFingerprints(nil); got != nil {
		t.Errorf("StreamFingerprints(nil) = %v, want nil", got)
	}
	got := StreamFingerprints([]appplugins.StreamFinding{
		{Entry: "policy-a", Fingerprint: "aaaa"},
		{Entry: "policy-a", Fingerprint: "bbbb"},
	})
	if len(got) != 2 || got[0] != "aaaa" || got[1] != "bbbb" {
		t.Errorf("StreamFingerprints() = %v, want [aaaa bbbb] in order", got)
	}
}

type hostSettings struct {
	Streaming StreamingSettings `mapstructure:"streaming"`
}

func TestStreamingDecodesFromASettingsMap(t *testing.T) {
	t.Parallel()
	cfg, err := Parse[hostSettings](map[string]any{
		"streaming": map[string]any{
			"enabled":                 true,
			"head_chars":              200,
			"min_chars_between_evals": 512,
			"max_hold_ms":             300,
			"max_accumulated_bytes":   8192,
			"final_pass":              false,
			"guard_timeout":           "5s",
			"on_error":                StreamOnErrorFailClosed,
		},
	})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	s := cfg.Streaming
	if !s.Enabled {
		t.Error("enabled did not decode")
	}
	if s.HeadChars != 200 || s.MinCharsBetweenEvals != 512 || s.MaxHoldMS != 300 ||
		s.MaxAccumulatedBytes != 8192 {
		t.Errorf("numeric keys did not decode: %+v", s)
	}
	if s.FinalPass == nil || *s.FinalPass {
		t.Error("an explicit final_pass: false must decode as a non-nil false")
	}
	if s.GuardTimeout != "5s" || s.OnError != StreamOnErrorFailClosed {
		t.Errorf("string keys did not decode: %+v", s)
	}
	if err := s.Validate("acme"); err != nil {
		t.Fatalf("decoded settings must validate, got %v", err)
	}
}

func TestAbsentStreamingBlockIsDisabled(t *testing.T) {
	t.Parallel()
	cfg, err := Parse[hostSettings](map[string]any{})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.Streaming.Enabled {
		t.Error("an absent streaming block must not enable per-block inspection")
	}
}
