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

const (
	matchStateMatchFound    = "MATCH_FOUND"
	invocationResultFailure = "FAILURE"
	executionStateSuccess   = "EXECUTION_SUCCESS"
)

// unevaluatedFilter names the first filter selected in block_on that reported
// an executionState other than EXECUTION_SUCCESS, or "" when every selected
// filter ran.
//
// This matters because a filter that failed to run and a filter that found
// nothing are otherwise indistinguishable to us: both arrive with no match,
// and the envelope's own invocationResult can still say SUCCESS. Treating the
// two alike would mean a guardrail quietly not guarding, which is the failure
// mode with no symptom.
//
// An empty executionState is treated as success: the field is absent on older
// filter versions, and inventing a failure from silence would fail every call
// closed against them.
func unevaluatedFilter(result *SanitizationResult, on map[string]bool) string {
	if result == nil {
		return ""
	}
	failed := func(state string) bool { return state != "" && state != executionStateSuccess }

	if on[filterSDP] {
		if sdp := result.sdp(); sdp != nil {
			switch {
			case sdp.DeidentifyResult != nil && failed(sdp.DeidentifyResult.ExecutionState),
				sdp.InspectResult != nil && failed(sdp.InspectResult.ExecutionState),
				sdp.RedactResult != nil && failed(sdp.RedactResult.ExecutionState):
				return filterSDP
			}
		}
	}
	if f := result.FilterResults.RAI; on[filterRAI] && f != nil && f.RaiFilterResult != nil &&
		failed(f.RaiFilterResult.ExecutionState) {
		return filterRAI
	}
	if f := result.FilterResults.PIAndJailbreak; on[filterPIAndJailbreak] && f != nil &&
		f.PiAndJailbreakFilterResult != nil && failed(f.PiAndJailbreakFilterResult.ExecutionState) {
		return filterPIAndJailbreak
	}
	if f := result.FilterResults.MaliciousURIs; on[filterMaliciousURIs] && f != nil &&
		f.MaliciousURIFilterResult != nil && failed(f.MaliciousURIFilterResult.ExecutionState) {
		return filterMaliciousURIs
	}
	if f := result.FilterResults.CSAM; on[filterCSAM] && f != nil && f.CSAMFilterFilterResult != nil &&
		failed(f.CSAMFilterFilterResult.ExecutionState) {
		return filterCSAM
	}
	return ""
}

// finding names the single filter that decided the outcome, plus the SDP
// info types when the match came from the sensitive-data-protection filter.
type finding struct {
	filter    string
	infoTypes []string
}

type assessmentResult struct {
	block     *finding
	anonymize *finding
}

// inspect walks a sanitize response's filterResults and decides the single
// outcome for this call: a block (the first matching filter, evaluated in a
// fixed order so the same response always names the same filter), or an
// anonymize when only SDP matched and its action is "anonymize".
//
// Block always wins over anonymize: if SDP matches with sdp_action=anonymize
// but another block_on filter also matches, the request is blocked, not
// silently anonymized and let through.
func inspect(result *SanitizationResult, cfg Settings) assessmentResult {
	var res assessmentResult
	if result == nil {
		return res
	}
	on := cfg.blockOnSet()

	var sdpAnonymize *finding
	if on[filterSDP] {
		f, isAnonymize := inspectSDP(result.FilterResults.SDP, cfg.SDPAction)
		if f != nil {
			if isAnonymize {
				sdpAnonymize = f
			} else {
				res.block = f
			}
		}
	}
	if res.block == nil && on[filterRAI] {
		res.block = inspectRAI(result.FilterResults.RAI)
	}
	if res.block == nil && on[filterPIAndJailbreak] {
		res.block = inspectPIAndJailbreak(result.FilterResults.PIAndJailbreak)
	}
	if res.block == nil && on[filterMaliciousURIs] {
		res.block = inspectMaliciousURIs(result.FilterResults.MaliciousURIs)
	}
	if res.block == nil && on[filterCSAM] {
		res.block = inspectCSAM(result.FilterResults.CSAM)
	}
	if res.block == nil && sdpAnonymize != nil {
		res.anonymize = sdpAnonymize
	}
	return res
}

// inspectSDP reports the SDP finding (if any) and whether it is an anonymize
// candidate rather than a block: SDP only anonymizes when the caller asked
// for it (sdp_action=anonymize) and Model Armor actually returned
// de-identified text to reinject.
// A template configured with only an inspect template reports inspectResult
// and never deidentifyResult, so reading deidentifyResult alone would miss
// the match entirely and let sensitive data through unflagged. Both shapes
// count as a match; only de-identified text can be anonymized.
func inspectSDP(f *SDPFilterResult, action string) (*finding, bool) {
	if f == nil || f.SdpFilterResult == nil {
		return nil, false
	}
	if d := f.SdpFilterResult.DeidentifyResult; d != nil && d.MatchState == matchStateMatchFound {
		find := &finding{filter: filterSDP, infoTypes: d.InfoTypes}
		if action == sdpActionAnonymize && d.Data != nil && d.Data.Text != "" {
			return find, true
		}
		return find, false
	}
	if i := f.SdpFilterResult.InspectResult; i != nil && i.MatchState == matchStateMatchFound {
		return &finding{filter: filterSDP, infoTypes: i.InfoTypes}, false
	}
	return nil, false
}

func inspectRAI(f *RAIFilterResult) *finding {
	if f == nil || f.RaiFilterResult == nil || f.RaiFilterResult.MatchState != matchStateMatchFound {
		return nil
	}
	return &finding{filter: filterRAI}
}

func inspectPIAndJailbreak(f *PIAndJailbreakFilterResult) *finding {
	if f == nil || f.PiAndJailbreakFilterResult == nil || f.PiAndJailbreakFilterResult.MatchState != matchStateMatchFound {
		return nil
	}
	return &finding{filter: filterPIAndJailbreak}
}

func inspectMaliciousURIs(f *MaliciousURIsFilterResult) *finding {
	if f == nil || f.MaliciousURIFilterResult == nil || f.MaliciousURIFilterResult.MatchState != matchStateMatchFound {
		return nil
	}
	return &finding{filter: filterMaliciousURIs}
}

func inspectCSAM(f *CSAMFilterResult) *finding {
	if f == nil || f.CSAMFilterFilterResult == nil || f.CSAMFilterFilterResult.MatchState != matchStateMatchFound {
		return nil
	}
	return &finding{filter: filterCSAM}
}
