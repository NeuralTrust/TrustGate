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

package openaimoderation

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const streamIDSeparator = ":"

const streamLegResponse = "response"

var _ appplugins.StreamInspector = (*Plugin)(nil)

// StreamSettings reports whether these policy settings ask for per-block
// moderation of the response leg, and the options the block loop must run
// under. Implementing InspectSegment is not the opt-in on its own: this plugin
// is on every pre_response chain that names it, so this is what keeps the head
// gate off for a policy that opted out with streaming.enabled: false.
func (p *Plugin) StreamSettings(settings map[string]any) (bool, appplugins.StreamOptions) {
	cfg, err := parseConfig(settings)
	if err != nil {
		return false, appplugins.StreamOptions{}
	}
	if !cfg.Streaming.IsEnabled() || !cfg.selectsStage(policy.StagePreResponse) {
		return false, appplugins.StreamOptions{}
	}
	return true, cfg.Streaming.Options()
}

// InspectSegment moderates one closed block of a streamed response.
//
// The text it moderates is seg.Accumulated, not seg.Text: a category is scored
// over a whole turn, and scoring a 300-character slice in isolation loses the
// context that made it a violation. The accumulated prefix is what the buffered
// leg would have seen had the response not been streamed, only shorter.
func (p *Plugin) InspectSegment(
	ctx context.Context,
	in appplugins.ExecInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentVerdict, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, appplugins.WrapExternalStreamFailure(PluginName, appplugins.FailureConfigInvalid, "", err)
	}
	p.warnUnknownConfig(ctx, in, cfg)
	if !cfg.Streaming.IsEnabled() || !cfg.selectsStage(policy.StagePreResponse) {
		return segmentAllow(), nil
	}
	if seg.Closing {
		p.recordStreamOutcome(ctx, in, cfg, seg)
		return segmentAllow(), nil
	}
	if p.baseURL == "" || p.client == nil {
		return segmentAllow(), nil
	}
	text := strings.TrimSpace(seg.Accumulated)
	if text == "" {
		return segmentAllow(), nil
	}

	// The deadline is the plugin's because the knob is in the plugin's schema,
	// and it is enforced here rather than left to the caller's context because
	// the caller is holding a client's bytes while this call runs.
	callCtx, cancel := context.WithTimeout(ctx, streamingDefaults.GuardTimeout)
	defer cancel()

	resp, err := p.client.Moderate(callCtx, p.baseURL, cfg.APIKey, moderationRequest{
		Model: cfg.Model,
		Input: []moderationInput{{Type: inputTypeText, Text: seg.Accumulated}},
	})
	if err != nil {
		// Returned rather than resolved here: only the guard knows whether the
		// status is still uncommitted, which decides whether the held text is
		// released; a guardrail that fails is always released. The guard itself
		// logs this failure (headFailure/blockFailure in stream_guard.go), so
		// this does not log a second time; it only tags the error with the
		// same reason vocabulary the buffered leg uses.
		return nil, appplugins.WrapExternalStreamFailure(PluginName, appplugins.FailureTransport, "",
			fmt.Errorf("moderating stream block %d: %w", seg.Seq, err))
	}
	if len(resp.Results) == 0 {
		return nil, appplugins.WrapExternalStreamFailure(PluginName, appplugins.FailureVerdictIncomplete, "",
			fmt.Errorf("stream block %d: moderations response carried no results", seg.Seq))
	}

	agg := aggregate(resp.Results)
	violations := evaluate(cfg, agg)
	if len(violations) == 0 {
		if missing := missingKnownThreshold(cfg, agg); missing != "" {
			return nil, appplugins.WrapExternalStreamFailure(PluginName, appplugins.FailureVerdictIncomplete, missing,
				fmt.Errorf("stream block %d: thresholded category %q missing from response", seg.Seq, missing))
		}
		return segmentAllow(), nil
	}
	return &appplugins.SegmentVerdict{
		Block:        true,
		Type:         typeContentFlagged,
		Message:      blockMessage(cfg),
		Fingerprints: violationFingerprints(in.Mode, violations),
	}, nil
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

	data := ModerationData{Model: cfg.Model, Streaming: stream}
	switch {
	case seg.Report.CutAtEval > 0:
		data.Decision = decisionBlock
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

	// A stream span's wall clock is the whole drain, provider generation
	// included, and the fold in pkg/app/metrics counts a pre_response span as
	// blocking. Left alone it would charge the provider's own time to the
	// policy chain. The guard latency is what the client actually waited for
	// this plugin.
	in.Event.SetSLatency(seg.Report.GuardLatency)
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, data.Decision)
}

// violationFingerprints identifies what was flagged, so that alert-only reports
// one incident per category per stream rather than one per block.
//
// The score is deliberately out of the key. It is computed over the text the
// call carried, so the same category on a longer prefix comes back with a
// different float and every block would look like a new finding. Which rule
// fired is in, because a category crossing its configured threshold and the
// same category merely flagged upstream are different incidents to an operator
// tuning thresholds.
//
// In the modes that block there is nothing to deduplicate: the first violation
// stops the stream, so no later block sees it again.
func violationFingerprints(mode policy.Mode, violations []violation) []string {
	if appplugins.Blocks(mode) {
		return nil
	}
	prints := make([]string, 0, len(violations))
	for _, v := range violations {
		rule := "flagged"
		if v.Threshold > 0 {
			rule = "threshold" + streamIDSeparator + strconv.FormatFloat(v.Threshold, 'f', -1, 64)
		}
		prints = append(prints, pluginutil.StreamFingerprint(PluginName, v.Category, rule))
	}
	return pluginutil.DedupeFingerprints(prints)
}

func blockMessage(cfg Settings) string {
	if msg := strings.TrimSpace(cfg.Action.Message); msg != "" {
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
