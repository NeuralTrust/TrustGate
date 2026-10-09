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

import appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"

const (
	matchStateMatchFound    = "MATCH_FOUND"
	invocationResultFailure = "FAILURE"
	// invocationResultPartial is Model Armor saying it ran only some of the
	// filters of the template. It blocks only through a skipped filter selected
	// in block_on (unevaluatedFilter); with every block_on filter run it is
	// recorded and fails open.
	invocationResultPartial = "PARTIAL"
	executionStateSuccess   = "EXECUTION_SUCCESS"
	executionStateSkipped   = "EXECUTION_SKIPPED"
)

// Reasons a filter selected in block_on produced no verdict. They are recorded
// on the event so an operator can tell a template that never enabled a filter
// (fix it in Google Cloud) from one whose filter failed on this call.
const (
	reasonFilterNotInTemplate = appplugins.DetailFilterNotInTemplate
	reasonFilterNotExecuted   = appplugins.DetailFilterNotExecuted
	// reasonFilterStateUnspecified is a filter whose executionState is neither
	// success nor a skip (EXECUTION_STATE_UNSPECIFIED, or a state Google adds):
	// nothing says the content caused it, so it is availability.
	reasonFilterStateUnspecified = appplugins.DetailFilterStateUnspecified
)

// unevaluatedFilter names the first filter selected in block_on that produced
// no verdict, and why, or "" when every selected filter ran.
//
// This matters because a filter that did not run and a filter that found
// nothing are otherwise indistinguishable to us: both arrive with no match,
// and the envelope's own invocationResult can still say SUCCESS. Treating the
// two alike would mean a guardrail quietly not guarding, which is the failure
// mode with no symptom.
//
// A filter can fail to run in two ways, and both count:
//   - it is absent from filterResults, which is what a template that never
//     enabled it returns. block_on defaults to every filter, so without this a
//     template enabling one filter would silently pass the other four.
//   - it is present with an executionState other than EXECUTION_SUCCESS. Only
//     EXECUTION_SKIPPED ("Detection skipped as token limit exceeded." above the
//     filter's token limit) is the content, not the template, keeping it from
//     running; any other state (EXECUTION_STATE_UNSPECIFIED) is Model Armor's
//     own and is reported as filter_state_unspecified.
//
// The three are told apart because they are not the same kind of failure: a
// skipped filter is the content's and is refused in a mode that blocks, while a
// filter the template never enabled is the customer's configuration and fails
// open. When both occur the skipped one is named, since it is the one a request
// can cause.
//
// An empty executionState on a present filter is treated as success: the
// field is absent on older filter versions, and inventing a failure from
// silence would fail every call closed against them.
func unevaluatedFilter(result *SanitizationResult, on map[string]bool) (filter, reason string) {
	if result == nil {
		return "", ""
	}
	fr := result.FilterResults

	var rai, pi, uris, csam *string
	if fr.RAI != nil && fr.RAI.RaiFilterResult != nil {
		rai = &fr.RAI.RaiFilterResult.ExecutionState
	}
	if fr.PIAndJailbreak != nil && fr.PIAndJailbreak.PiAndJailbreakFilterResult != nil {
		pi = &fr.PIAndJailbreak.PiAndJailbreakFilterResult.ExecutionState
	}
	if fr.MaliciousURIs != nil && fr.MaliciousURIs.MaliciousURIFilterResult != nil {
		uris = &fr.MaliciousURIs.MaliciousURIFilterResult.ExecutionState
	}
	if fr.CSAM != nil && fr.CSAM.CSAMFilterFilterResult != nil {
		csam = &fr.CSAM.CSAMFilterFilterResult.ExecutionState
	}
	checks := []struct {
		name    string
		present bool
		state   string
	}{
		{filterSDP, result.sdp() != nil, sdpState(result.sdp())},
		{filterRAI, rai != nil, stateOf(rai)},
		{filterPIAndJailbreak, pi != nil, stateOf(pi)},
		{filterMaliciousURIs, uris != nil, stateOf(uris)},
		{filterCSAM, csam != nil, stateOf(csam)},
	}
	missing, unspecified := "", ""
	for _, c := range checks {
		if !on[c.name] {
			continue
		}
		switch {
		case !c.present:
			if missing == "" {
				missing = c.name
			}
		case c.state == executionStateSkipped:
			return c.name, reasonFilterNotExecuted
		case c.state != "" && unspecified == "":
			unspecified = c.name
		}
	}
	if unspecified != "" {
		return unspecified, reasonFilterStateUnspecified
	}
	if missing != "" {
		return missing, reasonFilterNotInTemplate
	}
	return "", ""
}

func stateOf(state *string) string {
	if state == nil {
		return ""
	}
	return unsuccessfulState(*state)
}

// unsuccessfulState is the executionState of a present filter when it is not
// success, and "" when it succeeded. An empty state on a present filter is
// treated as success: the field is absent on older filter versions, and
// inventing a failure from silence would fail every call against them.
func unsuccessfulState(state string) string {
	if state == executionStateSuccess {
		return ""
	}
	return state
}

// sdpState is the unsuccessful executionState of the SDP filter, across the
// branches it answered with (inspect, de-identify or redact), or "" when every
// branch ran. A skip outranks any other state.
func sdpState(sdp *SDPResult) string {
	if sdp == nil {
		return ""
	}
	state := ""
	for _, branch := range []string{
		deidentifyState(sdp), inspectState(sdp), redactState(sdp),
	} {
		if branch == executionStateSkipped {
			return branch
		}
		if branch != "" && state == "" {
			state = branch
		}
	}
	return state
}

func deidentifyState(sdp *SDPResult) string {
	if sdp.DeidentifyResult == nil {
		return ""
	}
	return unsuccessfulState(sdp.DeidentifyResult.ExecutionState)
}

func inspectState(sdp *SDPResult) string {
	if sdp.InspectResult == nil {
		return ""
	}
	return unsuccessfulState(sdp.InspectResult.ExecutionState)
}

func redactState(sdp *SDPResult) string {
	if sdp.RedactResult == nil {
		return ""
	}
	return unsuccessfulState(sdp.RedactResult.ExecutionState)
}

// finding names the single filter that decided the outcome, plus the SDP
// info types when the match came from the sensitive-data-protection filter.
type finding struct {
	filter    string
	infoTypes []string
	// confidence is Model Armor's own confidence in the match, for the
	// filters that report one. Empty for those that do not (SDP, malicious
	// URIs and CSAM answer matched or not, with no degree).
	confidence string
	// category names the RAI sub-filter that matched — hate_speech,
	// dangerous, harassment, sexually_explicit. RAI reports confidence per
	// category rather than overall, so a confidence without the category it
	// belongs to would say nothing.
	category string
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

// RAI reports an overall match plus a per-category breakdown, and the
// confidence lives on the category rather than on the overall result. Pick
// the category that actually matched so "blocked by rai" becomes "blocked by
// rai/hate_speech at HIGH", which is the difference between a number someone
// can act on and one they cannot. Categories iterate in map order, so ties
// are broken by name to keep the same response naming the same category.
func inspectRAI(f *RAIFilterResult) *finding {
	if f == nil || f.RaiFilterResult == nil || f.RaiFilterResult.MatchState != matchStateMatchFound {
		return nil
	}
	found := &finding{filter: filterRAI}
	for name, cat := range f.RaiFilterResult.RaiFilterTypeResults {
		if cat.MatchState != matchStateMatchFound {
			continue
		}
		if found.category == "" || name < found.category {
			found.category = name
			found.confidence = cat.ConfidenceLevel
		}
	}
	return found
}

func inspectPIAndJailbreak(f *PIAndJailbreakFilterResult) *finding {
	if f == nil || f.PiAndJailbreakFilterResult == nil || f.PiAndJailbreakFilterResult.MatchState != matchStateMatchFound {
		return nil
	}
	return &finding{
		filter:     filterPIAndJailbreak,
		confidence: f.PiAndJailbreakFilterResult.ConfidenceLevel,
	}
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
