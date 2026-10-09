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
	"context"
	"fmt"
	"sort"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const streamIDSeparator = ":"

const streamLegResponse = "response"

var _ appplugins.StreamInspector = (*Plugin)(nil)

// StreamSettings reports whether these policy settings ask for per-block
// sanitization of the response leg, and the options the block loop must run
// under. Implementing InspectSegment is not the opt-in on its own: this plugin
// is on every pre_response chain that names it, so this is what keeps the head
// gate off for a policy that opted out with streaming.enabled: false.
func (p *Plugin) StreamSettings(settings map[string]any) (bool, appplugins.StreamOptions) {
	cfg, err := parseConfig(settings)
	if err != nil {
		return false, appplugins.StreamOptions{}
	}
	if !cfg.Streaming.IsEnabled() {
		return false, appplugins.StreamOptions{}
	}
	opts := cfg.Streaming.Options()
	opts.MaxAccumulatedBytes = min(opts.MaxAccumulatedBytes, maxSanitizeBytes)
	return true, opts
}

// InspectSegment sanitizes one closed block of a streamed response.
//
// Model Armor's REST v1 API has no streaming sanitize method, which is why the
// plugin used to sit out streamed responses entirely. It does not need one: the
// block loop hands over a growing prefix and each block is an ordinary
// SanitizeModelResponse call over that prefix, the same call the buffered leg
// makes over the whole completion.
//
// The prefix rather than the delta is what goes over, because every filter in a
// template decides over a whole turn; and the original user message goes with
// it, because SanitizeModelResponse correlates the response against the prompt
// that asked for it, and dropping that would change what the filters conclude.
func (p *Plugin) InspectSegment(
	ctx context.Context,
	in appplugins.ExecInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentVerdict, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, appplugins.WrapExternalStreamFailure(PluginName, appplugins.FailureConfigInvalid, "", err)
	}
	if !cfg.Streaming.IsEnabled() {
		return segmentAllow(), nil
	}
	if err := p.checkIdentity(cfg); err != nil {
		return nil, appplugins.WrapExternalStreamFailure(PluginName, appplugins.FailureConfigInvalid, "", err)
	}
	if seg.Closing {
		p.recordStreamOutcome(ctx, in, cfg, seg)
		return segmentAllow(), nil
	}
	if strings.TrimSpace(seg.Accumulated) == "" {
		return segmentAllow(), nil
	}
	cl, err := p.clientFor(cfg)
	if err != nil {
		return nil, appplugins.WrapExternalStreamFailure(PluginName, appplugins.FailureConfigInvalid, "",
			fmt.Errorf("resolving client for stream block %d: %w", seg.Seq, err))
	}

	// The deadline is enforced here because the caller is holding a client's
	// bytes for the length of this call, and the knob is in this plugin's
	// schema.
	callCtx, cancel := context.WithTimeout(ctx, streamingDefaults.GuardTimeout)
	defer cancel()

	result, err := cl.SanitizeModelResponse(
		callCtx, cfg.Project, cfg.Location, cfg.Template,
		seg.Accumulated, p.streamCorrelationPrompt(in),
	)
	if err != nil {
		// Resolved by the guard, not here: only it knows whether the status is
		// still uncommitted, which decides whether the held text is
		// released; a guardrail that fails is always released.
		return nil, appplugins.WrapExternalStreamFailure(PluginName, appplugins.FailureTransport, "",
			fmt.Errorf("sanitizing stream block %d: %w", seg.Seq, err))
	}

	if result.InvocationResult == invocationResultFailure {
		return nil, appplugins.WrapExternalStreamFailure(PluginName, appplugins.FailureTransport, "",
			fmt.Errorf("stream block %d: invocationResult FAILURE", seg.Seq))
	}

	res := inspect(result, cfg)
	// Same rule as the buffered leg: a block_on filter that produced no
	// verdict is not a clean one. It goes to the guard as an error, so
	// it fails open, and a real match on another filter still
	// wins because it is a verdict. A usable mask in a blocking mode is the
	// exception: the de-identified text is already in hand, and releasing the
	// original would send the raw PII, so the mask is applied and the incomplete
	// verdict rides along on it.
	var incomplete error
	if res.block == nil {
		if f, reason := unevaluatedFilter(result, cfg.blockOnSet()); f != "" {
			failure := appplugins.WrapExternalStreamFailure(PluginName, appplugins.FailureVerdictIncomplete, f,
				fmt.Errorf("stream block %d: filter %q selected in block_on produced no verdict (%s)", seg.Seq, f, reason))
			if _, usable := maskedText(result); res.anonymize == nil || !usable || !appplugins.Blocks(in.Mode) {
				return nil, failure
			}
			incomplete = failure
		}
	}
	switch {
	case res.block != nil:
		return &appplugins.SegmentVerdict{
			Block:        true,
			Type:         typeModelArmorBlocked,
			Message:      blockMessage(cfg),
			Fingerprints: findingFingerprints(in.Mode, res.block),
		}, nil
	case res.anonymize != nil:
		masked, ok := maskedText(result)
		if !ok {
			// The mask cannot be applied, so the block is released unmasked as a
			// failed inspection: the guard records it failed open with this reason.
			return nil, appplugins.WrapExternalStreamFailure(PluginName, appplugins.FailureVerdictIncomplete, reasonAnonymizeNoOutput,
				fmt.Errorf("stream block %d: guardrail asked to anonymise and returned no masked text", seg.Seq))
		}
		return &appplugins.SegmentVerdict{
			HasTransform: true,
			Transformed:  masked,
			Fingerprints: findingFingerprints(in.Mode, res.anonymize),
			Incomplete:   incomplete,
		}, nil
	default:
		return segmentAllow(), nil
	}
}

// streamCorrelationPrompt is the user message the streamed response is
// answering. It is best effort: without it the filters still run, they just
// lose the correlation, which is the same trade the buffered leg makes.
func (p *Plugin) streamCorrelationPrompt(in appplugins.ExecInput) string {
	if in.Request == nil || in.Request.Provider == "" {
		return ""
	}
	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return ""
	}
	return correlationPrompt(p.registry, format, in.Request.Body)
}

// recordStreamOutcome publishes this entry's account of the stream, once, on
// the closing segment. Span.SetExtras overwrites rather than merges, so a
// per-block write would leave the span carrying only the last block's account
// of a response that took several.
func (p *Plugin) recordStreamOutcome(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	seg appplugins.StreamSegment,
) {
	if in.Event == nil {
		return
	}
	stream := pluginutil.NewStreamData(streamID(ctx, seg), seg.Report)
	stream.Findings = pluginutil.StreamFingerprints(seg.Findings)

	data := &Data{
		Project:   cfg.Project,
		Location:  cfg.Location,
		Template:  cfg.Template,
		Mode:      string(in.Mode),
		Streaming: stream,
	}
	switch {
	case seg.Report.CutAtEval > 0:
		data.Decision = pluginutil.StreamCutDecision(seg.Report, decisionBlocked)
	case seg.Report.MaskedEvals > 0:
		// With no cut the guard applied every mask, as the buffered leg does.
		data.Decision = decisionAnonymized
	case len(stream.Findings) > 0:
		data.Decision = decisionReported
	// A positive finding outranks a missing inspection, so a failure only labels
	// a stream that reported nothing.
	case pluginutil.StreamFailedOpen(seg.Report):
		data.Decision = appplugins.DecisionFailedOpen
	default:
		data.Decision = decisionAllowed
	}

	// The first failed block's reason travels whatever the decision above
	// settled on: a later finding, mask or cut does not erase that an earlier
	// block went uninspected. Extras are replaced, so this one write is the
	// only place it can land.
	data.FailureReason, data.FailureDetail = pluginutil.StreamFailure(seg.Report)
	data.FailureClass = pluginutil.StreamFailureClass(seg.Report)
	if isAnonymizeReason(data.FailureDetail) {
		data.Degraded = true
		data.DegradedReason = data.FailureDetail
	}

	// A stream span's wall clock is the whole drain, provider generation
	// included, and the fold in pkg/app/metrics counts a pre_response span as
	// blocking. The guard latency is what the client actually waited for this
	// plugin.
	in.Event.SetSLatency(seg.Report.GuardLatency)
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, data.Decision)
}

// findingFingerprints identifies what matched, so that alert-only reports one
// incident per stream instead of one per block.
//
// One key per info type rather than one for the set: SDP reports the types it
// found in the text it was given, so the set grows as the prefix does. Keyed as
// a set, "EMAIL" and then "EMAIL, PHONE" would be two incidents for what is one
// email and one phone number; keyed per type, each appears once however many
// blocks carry it.
//
// confidence is out of the key. It is Model Armor's degree of belief over the
// text the call carried, so a match can move from one bucket to another as the
// prefix grows and would split a single incident in two.
func findingFingerprints(mode policy.Mode, f *finding) []string {
	if f == nil || appplugins.Blocks(mode) {
		return nil
	}
	if len(f.infoTypes) == 0 {
		return pluginutil.DedupeFingerprints([]string{
			pluginutil.StreamFingerprint(PluginName, f.filter, f.category),
		})
	}
	types := append([]string(nil), f.infoTypes...)
	sort.Strings(types)
	prints := make([]string, 0, len(types))
	for _, infoType := range types {
		prints = append(prints, pluginutil.StreamFingerprint(PluginName, f.filter, f.category, infoType))
	}
	return pluginutil.DedupeFingerprints(prints)
}

func blockMessage(cfg Settings) string {
	if msg := strings.TrimSpace(cfg.Message); msg != "" {
		return msg
	}
	return appplugins.DefaultBlockMessage
}

// streamID correlates every block of one response. An empty id is not a missing
// one but a shared one, so the trace id is preferred and the guard's own id is
// the fallback.
func streamID(ctx context.Context, seg appplugins.StreamSegment) string {
	if rt := trace.FromContext(ctx); rt != nil && rt.TraceID() != "" {
		return rt.TraceID() + streamIDSeparator + streamLegResponse
	}
	return strings.TrimSpace(seg.StreamID)
}

func segmentAllow() *appplugins.SegmentVerdict {
	return &appplugins.SegmentVerdict{}
}

// isAnonymizeReason reports whether a failure detail is one of the reasons a
// provider's mask could not be applied, which the span also flags as degraded.
func isAnonymizeReason(detail string) bool {
	switch detail {
	case reasonAnonymizeNoOutput, reasonAnonymizeUnsupportedFormat, reasonAnonymizeEncodeFailed:
		return true
	}
	return false
}
