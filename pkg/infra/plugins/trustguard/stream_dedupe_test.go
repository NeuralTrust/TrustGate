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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

func injectionFinding() GuardFinding {
	return GuardFinding{
		Source: &GuardFindingSource{
			Kind:         "detector",
			Plugin:       "prompt_guard",
			DetectorID:   "pg-1",
			DetectorName: "Prompt Guard",
			PolicyID:     "pol-1",
			GateName:     "output",
		},
		Signal:  &GuardFindingSignal{Type: "prompt_injection", Confidence: 0.81},
		Outcome: &GuardFindingOutcome{Action: "block"},
	}
}

func piiFinding() GuardFinding {
	return GuardFinding{
		Source:  &GuardFindingSource{Kind: "detector", Plugin: "data_loss_prevention"},
		Signal:  &GuardFindingSignal{Type: "pii", Confidence: 0.4},
		Outcome: &GuardFindingOutcome{Action: "transform"},
	}
}

func TestFindingFingerprintKeysOnIdentityOnly(t *testing.T) {
	t.Parallel()

	base := injectionFinding()
	tests := []struct {
		name  string
		build func() GuardFinding
		same  bool
	}{
		{
			name:  "the same finding",
			build: injectionFinding,
			same:  true,
		},
		{
			name: "a confidence that drifted as more text arrived",
			build: func() GuardFinding {
				f := injectionFinding()
				f.Signal.Confidence = 0.97
				return f
			},
			same: true,
		},
		{
			name: "different evidence over the same detection",
			build: func() GuardFinding {
				f := injectionFinding()
				f.Evidence = map[string]any{"matched_text": "ignore all previous instructions"}
				return f
			},
			same: true,
		},
		{
			name: "another detector",
			build: func() GuardFinding {
				f := injectionFinding()
				f.Source.DetectorID = "pg-2"
				return f
			},
		},
		{
			name: "another signal type",
			build: func() GuardFinding {
				f := injectionFinding()
				f.Signal.Type = "toxicity"
				return f
			},
		},
		{
			name: "another enforced action",
			build: func() GuardFinding {
				f := injectionFinding()
				f.Outcome.Action = "transform"
				return f
			},
		},
		{
			name:  "a different finding entirely",
			build: piiFinding,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := findingFingerprint(tt.build())
			require.NotEmpty(t, got)
			assert.Len(t, got, fingerprintBytes*2, "the digest is hex of a fixed width")
			if tt.same {
				assert.Equal(t, findingFingerprint(base), got)
				return
			}
			assert.NotEqual(t, findingFingerprint(base), got)
		})
	}
}

// A finding the engine sent with nothing to identify it by is not
// fingerprinted: one empty key would fold every such finding in the stream into
// a single entry, which is the opposite of what the set is for.
func TestFindingFingerprintRefusesAFindingWithNoIdentity(t *testing.T) {
	t.Parallel()

	tests := map[string]GuardFinding{
		"nothing at all":        {},
		"evidence only":         {Evidence: map[string]any{"matched_text": "secret"}},
		"blank identity fields": {Source: &GuardFindingSource{Plugin: "  "}, Signal: &GuardFindingSignal{Confidence: 0.9}},
	}

	for name, finding := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Empty(t, findingFingerprint(finding))
		})
	}
}

func TestStreamFingerprintsOnlyInAlertOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode policy.Mode
		want int
	}{
		{name: "enforce stops the stream on its first verdict and reads no key back", mode: policy.ModeEnforce},
		{name: "throttle blocks too", mode: policy.ModeThrottle},
		{name: "observe keeps calling over a cumulative payload", mode: policy.ModeObserve, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, unidentified := streamFingerprints(tt.mode, []GuardFinding{injectionFinding(), piiFinding()})
			assert.Len(t, got, tt.want)
			assert.Zero(t, unidentified)
		})
	}
}

// A finding the engine sent with nothing to identify it by is counted rather
// than keyed. No placeholder stands in for it: one would fold every such
// finding in the stream into a single entry, and the count is what says the
// stream was not as quiet as its empty set suggests.
func TestStreamFingerprintsCollapsesRepeatsAndCountsTheUnidentified(t *testing.T) {
	t.Parallel()

	got, unidentified := streamFingerprints(policy.ModeObserve, []GuardFinding{
		injectionFinding(),
		injectionFinding(),
		{Evidence: map[string]any{"matched_text": "unidentified"}},
	})
	assert.Equal(t, []string{findingFingerprint(injectionFinding())}, got)
	assert.Equal(t, 1, unidentified)
}
