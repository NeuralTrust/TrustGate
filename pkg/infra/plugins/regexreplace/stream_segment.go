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

package regexreplace

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const streamIDSeparator = ":"

const streamLegResponse = "response"

var _ appplugins.StreamInspector = (*Plugin)(nil)

// StreamSettings reports whether these policy settings ask for per-block
// rewriting of the response leg, and the options the block loop must run
// under. A policy targeting the request is not on the response leg at all, so
// it never opts in however its streaming block is filled.
func (p *Plugin) StreamSettings(settings map[string]any) (bool, appplugins.StreamOptions) {
	if _, ok := settings["streaming"]; !ok {
		return false, appplugins.StreamOptions{}
	}
	cfg, err := parseConfig(settings)
	if err != nil {
		return false, appplugins.StreamOptions{}
	}
	if !cfg.Streaming.Enabled || cfg.Target != targetResponse {
		return false, appplugins.StreamOptions{}
	}
	return true, cfg.Streaming.Options()
}

// InspectSegment rewrites one closed block of a streamed response.
//
// The rules run over seg.Accumulated rather than seg.Text because a pattern can
// straddle a block boundary: a card number split across two deltas matches
// neither of them on its own. Running over the prefix each time is quadratic in
// the length of the response, which is what the streaming cadence defaults are
// sized to bound.
//
// This plugin never blocks. Its whole job is to rewrite, so the verdict it
// returns is a transform and nothing else; where the matched span has already
// reached the client the guard cuts, because masking text that has left is not
// possible and releasing it is what the rules exist to prevent.
func (p *Plugin) InspectSegment(
	ctx context.Context,
	in appplugins.ExecInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentVerdict, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("regex_replace: %w", err)
	}
	if !cfg.Streaming.Enabled || cfg.Target != targetResponse {
		return segmentAllow(), nil
	}
	if seg.Closing {
		p.recordStreamOutcome(ctx, in, cfg, seg)
		return segmentAllow(), nil
	}
	if seg.Accumulated == "" {
		return segmentAllow(), nil
	}

	masked, changed := applyRules(cfg.compiled, seg.Accumulated)
	if !changed {
		// A transform whose output equals the produced text ends the stream:
		// the guard cannot tell "nothing matched" from "a mask the guard
		// already applied was handed back unchanged", and releasing on the
		// wrong reading releases what the rules asked to mask. Saying nothing
		// matched is what keeps a clean response streaming.
		return segmentAllow(), nil
	}
	return &appplugins.SegmentVerdict{
		HasTransform: true,
		Transformed:  masked,
		Fingerprints: ruleFingerprints(cfg, seg.Accumulated),
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

	data := &Data{
		Target:    cfg.Target,
		Stage:     string(in.Stage),
		Mode:      string(in.Mode),
		Changed:   len(stream.Findings) > 0 || seg.Report.CutAtEval > 0,
		Streaming: stream,
	}
	switch {
	case seg.Report.CutAtEval > 0:
		// The only way this plugin ends a stream is a rewrite the guard could
		// not land, so a cut here is a rewrite that did not happen rather than
		// a policy decision to stop the response.
		data.Decision = decisionRewriteUnapplied
	case data.Changed:
		data.Decision = decisionRewritten
	default:
		data.Decision = decisionNoMatch
	}

	in.Event.SetSLatency(seg.Report.GuardLatency)
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, data.Decision)
}

// ruleFingerprints names which rules matched, so that a stream reports one
// incident per rule instead of one per block.
//
// Unlike the guardrail plugins, this one reports in every mode. They skip the
// blocking modes because a finding there ends the stream, so no later block
// comes back carrying it; this plugin never ends a stream, so enforce keeps
// calling and the set is what says a response was rewritten at all. Repeats
// still collapse on their own: the guard rewrites the accumulated buffer in
// place, so a later block carries the masked text and the rule that produced
// it no longer matches.
//
// The key is the rule's pattern and its position, never the text it matched:
// the matched span is response content, and a digest of it on a span that
// publishes to OTLP is a second route for exactly the data these rules exist to
// remove. Position is in because two rules can share a pattern with different
// replacements, and an operator reading the set needs to know which one fired.
func ruleFingerprints(cfg Settings, text string) []string {
	prints := make([]string, 0, len(cfg.compiled))
	for i, rule := range cfg.compiled {
		if rule.re.MatchString(text) {
			prints = append(prints, pluginutil.StreamFingerprint(
				PluginName, strconv.Itoa(i), rule.re.String(),
			))
		}
	}
	return pluginutil.DedupeFingerprints(prints)
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
