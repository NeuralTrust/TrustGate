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

package googlemodelarmor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allBlockOnSettings() Settings {
	return Settings{BlockOn: append([]string(nil), allFilters...), SDPAction: sdpActionBlock}
}

func TestInspectNilResult(t *testing.T) {
	t.Parallel()
	res := inspect(nil, allBlockOnSettings())
	assert.Nil(t, res.block)
	assert.Nil(t, res.anonymize)
}

func TestInspectNoMatch(t *testing.T) {
	t.Parallel()
	res := inspect(&SanitizationResult{FilterMatchState: "NO_MATCH_FOUND"}, allBlockOnSettings())
	assert.Nil(t, res.block)
	assert.Nil(t, res.anonymize)
}

func TestInspectSDPBlocksByDefault(t *testing.T) {
	t.Parallel()
	result := &SanitizationResult{FilterResults: FilterResults{
		SDP: &SDPFilterResult{SdpFilterResult: &SDPResult{DeidentifyResult: &SDPDeidentifyResult{
			MatchState: matchStateMatchFound,
			InfoTypes:  []string{"EMAIL_ADDRESS"},
			Data:       &SDPData{Text: "redacted"},
		}}},
	}}
	res := inspect(result, allBlockOnSettings())
	require.NotNil(t, res.block)
	assert.Nil(t, res.anonymize)
	assert.Equal(t, filterSDP, res.block.filter)
	assert.Equal(t, []string{"EMAIL_ADDRESS"}, res.block.infoTypes)
}

func TestInspectSDPAnonymizeWhenConfigured(t *testing.T) {
	t.Parallel()
	cfg := allBlockOnSettings()
	cfg.SDPAction = sdpActionAnonymize
	result := &SanitizationResult{FilterResults: FilterResults{
		SDP: &SDPFilterResult{SdpFilterResult: &SDPResult{DeidentifyResult: &SDPDeidentifyResult{
			MatchState: matchStateMatchFound,
			InfoTypes:  []string{"EMAIL_ADDRESS"},
			Data:       &SDPData{Text: "redacted"},
		}}},
	}}
	res := inspect(result, cfg)
	assert.Nil(t, res.block)
	require.NotNil(t, res.anonymize)
	assert.Equal(t, filterSDP, res.anonymize.filter)
}

func TestInspectSDPAnonymizeConfiguredButNoDeidentifiedTextBlocks(t *testing.T) {
	t.Parallel()
	cfg := allBlockOnSettings()
	cfg.SDPAction = sdpActionAnonymize
	result := &SanitizationResult{FilterResults: FilterResults{
		SDP: &SDPFilterResult{SdpFilterResult: &SDPResult{DeidentifyResult: &SDPDeidentifyResult{
			MatchState: matchStateMatchFound,
			// No Data: Model Armor flagged it but returned no de-identified text.
		}}},
	}}
	res := inspect(result, cfg)
	require.NotNil(t, res.block)
	assert.Nil(t, res.anonymize)
}

func TestInspectBlockWinsOverAnonymize(t *testing.T) {
	t.Parallel()
	cfg := allBlockOnSettings()
	cfg.SDPAction = sdpActionAnonymize
	result := &SanitizationResult{FilterResults: FilterResults{
		SDP: &SDPFilterResult{SdpFilterResult: &SDPResult{DeidentifyResult: &SDPDeidentifyResult{
			MatchState: matchStateMatchFound,
			Data:       &SDPData{Text: "redacted"},
		}}},
		CSAM: &CSAMFilterResult{CSAMFilterFilterResult: &CSAMResult{MatchState: matchStateMatchFound}},
	}}
	res := inspect(result, cfg)
	require.NotNil(t, res.block)
	assert.Equal(t, filterCSAM, res.block.filter)
	assert.Nil(t, res.anonymize)
}

func TestInspectRAI(t *testing.T) {
	t.Parallel()
	result := &SanitizationResult{FilterResults: FilterResults{
		RAI: &RAIFilterResult{RaiFilterResult: &RAIResult{MatchState: matchStateMatchFound}},
	}}
	res := inspect(result, allBlockOnSettings())
	require.NotNil(t, res.block)
	assert.Equal(t, filterRAI, res.block.filter)
}

func TestInspectPIAndJailbreak(t *testing.T) {
	t.Parallel()
	result := &SanitizationResult{FilterResults: FilterResults{
		PIAndJailbreak: &PIAndJailbreakFilterResult{
			PiAndJailbreakFilterResult: &PIAndJailbreakResult{MatchState: matchStateMatchFound},
		},
	}}
	res := inspect(result, allBlockOnSettings())
	require.NotNil(t, res.block)
	assert.Equal(t, filterPIAndJailbreak, res.block.filter)
}

func TestInspectMaliciousURIs(t *testing.T) {
	t.Parallel()
	result := &SanitizationResult{FilterResults: FilterResults{
		MaliciousURIs: &MaliciousURIsFilterResult{
			MaliciousURIFilterResult: &MaliciousURIResult{MatchState: matchStateMatchFound},
		},
	}}
	res := inspect(result, allBlockOnSettings())
	require.NotNil(t, res.block)
	assert.Equal(t, filterMaliciousURIs, res.block.filter)
}

func TestInspectCSAM(t *testing.T) {
	t.Parallel()
	result := &SanitizationResult{FilterResults: FilterResults{
		CSAM: &CSAMFilterResult{CSAMFilterFilterResult: &CSAMResult{MatchState: matchStateMatchFound}},
	}}
	res := inspect(result, allBlockOnSettings())
	require.NotNil(t, res.block)
	assert.Equal(t, filterCSAM, res.block.filter)
}

func TestInspectIgnoresFilterNotInBlockOn(t *testing.T) {
	t.Parallel()
	cfg := Settings{BlockOn: []string{filterCSAM}, SDPAction: sdpActionBlock}
	result := &SanitizationResult{FilterResults: FilterResults{
		RAI: &RAIFilterResult{RaiFilterResult: &RAIResult{MatchState: matchStateMatchFound}},
	}}
	res := inspect(result, cfg)
	assert.Nil(t, res.block, "rai matched but is not in block_on, so it must not block")
}

func TestInspectFirstMatchInCanonicalOrderNames(t *testing.T) {
	t.Parallel()
	result := &SanitizationResult{FilterResults: FilterResults{
		RAI:  &RAIFilterResult{RaiFilterResult: &RAIResult{MatchState: matchStateMatchFound}},
		CSAM: &CSAMFilterResult{CSAMFilterFilterResult: &CSAMResult{MatchState: matchStateMatchFound}},
	}}
	res := inspect(result, allBlockOnSettings())
	require.NotNil(t, res.block)
	assert.Equal(t, filterRAI, res.block.filter, "rai is evaluated before csam")
}

func TestInspectPIAndJailbreakCarriesConfidence(t *testing.T) {
	t.Parallel()

	f := inspectPIAndJailbreak(&PIAndJailbreakFilterResult{
		PiAndJailbreakFilterResult: &PIAndJailbreakResult{
			MatchState: matchStateMatchFound, ConfidenceLevel: "HIGH",
		},
	})
	if f == nil {
		t.Fatal("expected a finding")
	}
	if f.confidence != "HIGH" {
		t.Errorf("confidence = %q, want HIGH", f.confidence)
	}
	if f.category != "" {
		t.Errorf("pi_and_jailbreak has no sub-category, got %q", f.category)
	}
}

// RAI carries its confidence on the sub-category, not the overall result, so
// a finding that reported only "rai" would carry a confidence belonging to
// nothing in particular.
func TestInspectRAINamesTheMatchedCategoryAndItsConfidence(t *testing.T) {
	t.Parallel()

	f := inspectRAI(&RAIFilterResult{RaiFilterResult: &RAIResult{
		MatchState: matchStateMatchFound,
		RaiFilterTypeResults: map[string]RAIFilterTypeResult{
			"sexually_explicit": {MatchState: "NO_MATCH_FOUND"},
			"hate_speech":       {MatchState: matchStateMatchFound, ConfidenceLevel: "MEDIUM"},
			"harassment":        {MatchState: "NO_MATCH_FOUND"},
			"dangerous":         {MatchState: "NO_MATCH_FOUND"},
		},
	}})
	if f == nil {
		t.Fatal("expected a finding")
	}
	if f.category != "hate_speech" {
		t.Errorf("category = %q, want hate_speech", f.category)
	}
	if f.confidence != "MEDIUM" {
		t.Errorf("confidence = %q, want MEDIUM", f.confidence)
	}
}

// Map iteration order is random in Go, so without a tiebreak the same
// response could name a different category on each call and nobody tuning
// thresholds could trust what they were reading.
func TestInspectRAIBreaksTiesDeterministically(t *testing.T) {
	t.Parallel()

	in := &RAIFilterResult{RaiFilterResult: &RAIResult{
		MatchState: matchStateMatchFound,
		RaiFilterTypeResults: map[string]RAIFilterTypeResult{
			"hate_speech": {MatchState: matchStateMatchFound, ConfidenceLevel: "HIGH"},
			"dangerous":   {MatchState: matchStateMatchFound, ConfidenceLevel: "LOW"},
			"harassment":  {MatchState: matchStateMatchFound, ConfidenceLevel: "MEDIUM"},
		},
	}}
	for i := 0; i < 50; i++ {
		f := inspectRAI(in)
		if f.category != "dangerous" || f.confidence != "LOW" {
			t.Fatalf("iteration %d picked %q/%q, want dangerous/LOW every time", i, f.category, f.confidence)
		}
	}
}

// An overall RAI match with no per-category breakdown must still be a
// finding; some responses carry only the overall state.
func TestInspectRAIWithoutCategoryBreakdownStillMatches(t *testing.T) {
	t.Parallel()

	f := inspectRAI(&RAIFilterResult{RaiFilterResult: &RAIResult{MatchState: matchStateMatchFound}})
	if f == nil {
		t.Fatal("expected a finding even with no category breakdown")
	}
	if f.category != "" || f.confidence != "" {
		t.Errorf("nothing to report, got category=%q confidence=%q", f.category, f.confidence)
	}
}
