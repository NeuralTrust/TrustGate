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
		SDP: &SDPFilterResult{DeidentifyResult: &SDPDeidentifyResult{
			MatchState: matchStateMatchFound,
			InfoTypes:  []string{"EMAIL_ADDRESS"},
			Data:       &SDPData{Text: "redacted"},
		}},
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
		SDP: &SDPFilterResult{DeidentifyResult: &SDPDeidentifyResult{
			MatchState: matchStateMatchFound,
			InfoTypes:  []string{"EMAIL_ADDRESS"},
			Data:       &SDPData{Text: "redacted"},
		}},
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
		SDP: &SDPFilterResult{DeidentifyResult: &SDPDeidentifyResult{
			MatchState: matchStateMatchFound,
			// No Data: Model Armor flagged it but returned no de-identified text.
		}},
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
		SDP: &SDPFilterResult{DeidentifyResult: &SDPDeidentifyResult{
			MatchState: matchStateMatchFound,
			Data:       &SDPData{Text: "redacted"},
		}},
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
