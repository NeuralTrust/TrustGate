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

package bedrockguardrail

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const streamIDSeparator = ":"

const streamLegResponse = "response"

const (
	defaultBlockMessage = "response blocked by guardrail policy"
	// The buffered leg blocks when the guardrail asks to anonymise and gives
	// nothing to anonymise with, so the stream leg cuts for the same reason
	// rather than releasing text the policy ruled out.
	anonymizeDegradedMessage = "response blocked: guardrail masking could not be applied to this stream"
)

var _ appplugins.StreamInspector = (*Plugin)(nil)

// StreamSettings reports whether these policy settings ask for per-block
// inspection of the response leg, and the options the block loop must run
// under. Implementing InspectSegment is not the opt-in on its own: this plugin
// is on every pre_response chain that names it, and streaming.enabled defaults
// to false, so without this the head gate would be built for policies that
// never asked for it.
func (p *Plugin) StreamSettings(settings map[string]any) (bool, appplugins.StreamOptions) {
	if _, ok := settings["streaming"]; !ok {
		return false, appplugins.StreamOptions{}
	}
	cfg, err := parseConfig(settings)
	if err != nil {
		return false, appplugins.StreamOptions{}
	}
	if !cfg.Streaming.Enabled {
		return false, appplugins.StreamOptions{}
	}
	return true, cfg.Streaming.Options()
}

// InspectSegment applies the guardrail to one closed block of a streamed
// response.
//
// It inspects seg.Accumulated rather than seg.Text because a guardrail decides
// over a whole turn: a topic or a word policy that a block trips halfway
// through its own text is invisible to a call that only carries that block.
//
// An anonymise outcome comes back as a transform over the same prefix, not as a
// rewritten slice. SegmentVerdict.Transformed replaces the whole of
// seg.Accumulated, and ApplyGuardrail already returns the masked form of
// exactly the text it was given, so the two line up without splicing. Where the
// masked span has already reached the client the guard cuts instead — masking
// text that has left is not possible, and passing it silently would be worse.
func (p *Plugin) InspectSegment(
	ctx context.Context,
	in appplugins.ExecInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentVerdict, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("bedrock_guardrail: %w", err)
	}
	if !cfg.Streaming.Enabled {
		return segmentAllow(), nil
	}
	if seg.Closing {
		p.recordStreamOutcome(ctx, in, cfg, seg)
		return segmentAllow(), nil
	}
	if p.guardrails == nil || strings.TrimSpace(seg.Accumulated) == "" {
		return segmentAllow(), nil
	}

	// The deadline is enforced here because the caller is holding a client's
	// bytes for the length of this call, and the knob is in this plugin's
	// schema.
	callCtx, cancel := context.WithTimeout(ctx, cfg.Streaming.Timeout(streamingDefaults.GuardTimeout))
	defer cancel()

	out, err := p.guardrails.ApplyGuardrail(
		callCtx,
		credentialsFromConfig(cfg.Credentials),
		buildApplyInput(cfg, seg.Accumulated, types.GuardrailContentSourceOutput),
	)
	if err != nil {
		// Resolved by the guard, not here: only it knows whether the status is
		// still uncommitted, which is what makes streaming.on_error a clean 403
		// at the head and a terminator after it.
		return nil, fmt.Errorf("bedrock_guardrail: applying guardrail to stream block %d: %w", seg.Seq, err)
	}

	res := inspect(out, cfg.PIIAction)
	switch {
	case res.block != nil:
		return &appplugins.SegmentVerdict{
			Block:        true,
			Type:         typeGuardrailBlocked,
			Message:      blockMessage(cfg),
			Fingerprints: findingFingerprints(in.Mode, res.block),
		}, nil
	case res.anonymize != nil:
		masked, ok := maskedText(out)
		if !ok {
			// The guardrail said to anonymise and gave nothing to anonymise
			// with. Releasing the unmasked text would be the one outcome the
			// policy ruled out, so this is a cut.
			return &appplugins.SegmentVerdict{
				Block:        true,
				Type:         typeGuardrailBlocked,
				Message:      anonymizeDegradedMessage,
				Fingerprints: findingFingerprints(in.Mode, res.anonymize),
			}, nil
		}
		return &appplugins.SegmentVerdict{
			HasTransform: true,
			Transformed:  masked,
			Fingerprints: findingFingerprints(in.Mode, res.anonymize),
		}, nil
	default:
		return segmentAllow(), nil
	}
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
		GuardrailID: cfg.GuardrailID,
		Version:     cfg.Version,
		Region:      cfg.Credentials.AWSRegion,
		Mode:        string(in.Mode),
		Streaming:   stream,
	}
	switch {
	case seg.Report.CutAtEval > 0:
		data.Decision = decisionBlocked
	case len(stream.Findings) > 0:
		data.Decision = decisionReported
	default:
		data.Decision = decisionAllowed
	}

	// A stream span's wall clock is the whole drain, provider generation
	// included, and the fold in pkg/app/metrics counts a pre_response span as
	// blocking. The guard latency is what the client actually waited for this
	// plugin.
	in.Event.SetSLatency(seg.Report.GuardLatency)
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, data.Decision)
}

// findingFingerprints identifies what the guardrail matched, so that alert-only
// reports one incident per stream instead of one per block.
//
// Every field of a finding is a label the guardrail configuration owns, so none
// of them moves as the prefix grows, and none carries the matched text. In the
// modes that block there is nothing to deduplicate: the first finding stops the
// stream, so no later block sees it again.
func findingFingerprints(mode policy.Mode, f *finding) []string {
	if f == nil || appplugins.Blocks(mode) {
		return nil
	}
	fp := pluginutil.StreamFingerprint(PluginName, f.policy, f.name, f.matchType, f.action)
	return pluginutil.DedupeFingerprints([]string{fp})
}

func blockMessage(cfg Settings) string {
	if msg := strings.TrimSpace(cfg.Message); msg != "" {
		return msg
	}
	return defaultBlockMessage
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
