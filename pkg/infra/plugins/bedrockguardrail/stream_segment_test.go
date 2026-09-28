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
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

type scriptedGuardrail struct {
	calls   int
	inputs  []string
	sources []types.GuardrailContentSource
	apply   func(*bedrockruntime.ApplyGuardrailInput) (*bedrockruntime.ApplyGuardrailOutput, error)
}

func (s *scriptedGuardrail) ApplyGuardrail(
	_ context.Context,
	in *bedrockruntime.ApplyGuardrailInput,
	_ ...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	s.calls++
	s.sources = append(s.sources, in.Source)
	for _, c := range in.Content {
		if text, ok := c.(*types.GuardrailContentBlockMemberText); ok {
			s.inputs = append(s.inputs, aws.ToString(text.Value.Text))
		}
	}
	return s.apply(in)
}

func streamPlugin(t *testing.T, g *scriptedGuardrail) *Plugin {
	t.Helper()
	p := New(adapter.NewRegistry(), nil)
	p.guardrails = &cachedGuardrailClient{cache: &clientCache{
		build: func(context.Context, awsCredentials) (guardrailClient, error) { return g, nil },
	}}
	return p
}

func allowing() *scriptedGuardrail {
	return &scriptedGuardrail{apply: func(*bedrockruntime.ApplyGuardrailInput) (*bedrockruntime.ApplyGuardrailOutput, error) {
		return &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}, nil
	}}
}

func intervening(out *bedrockruntime.ApplyGuardrailOutput) *scriptedGuardrail {
	return &scriptedGuardrail{apply: func(*bedrockruntime.ApplyGuardrailInput) (*bedrockruntime.ApplyGuardrailOutput, error) {
		return out, nil
	}}
}

func blockingOutput() *bedrockruntime.ApplyGuardrailOutput {
	return &bedrockruntime.ApplyGuardrailOutput{
		Action: types.GuardrailActionGuardrailIntervened,
		Assessments: []types.GuardrailAssessment{{
			ContentPolicy: &types.GuardrailContentPolicyAssessment{
				Filters: []types.GuardrailContentFilter{{
					Type:   types.GuardrailContentFilterTypeHate,
					Action: types.GuardrailContentPolicyActionBlocked,
				}},
			},
		}},
	}
}

func anonymisingOutput(masked string) *bedrockruntime.ApplyGuardrailOutput {
	out := &bedrockruntime.ApplyGuardrailOutput{
		Action: types.GuardrailActionGuardrailIntervened,
		Assessments: []types.GuardrailAssessment{{
			SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
				PiiEntities: []types.GuardrailPiiEntityFilter{{
					Type:   types.GuardrailPiiEntityTypeEmail,
					Action: types.GuardrailSensitiveInformationPolicyActionAnonymized,
				}},
			},
		}},
	}
	if masked != "" {
		out.Outputs = []types.GuardrailOutputContent{{Text: aws.String(masked)}}
	}
	return out
}

func streamSettings(over map[string]any) map[string]any {
	stream := map[string]any{"enabled": true}
	for k, v := range over {
		stream[k] = v
	}
	return map[string]any{
		"guardrail_id": "gr-1",
		"pii_action":   piiActionAnonymize,
		"credentials": map[string]any{
			"access_key_id":     "AKIAEXAMPLE",
			"secret_access_key": "secret",
		},
		"streaming": stream,
	}
}

func bufferedSettings() map[string]any {
	s := streamSettings(nil)
	delete(s, "streaming")
	return s
}

func segment(seq int, accumulated string) appplugins.StreamSegment {
	return appplugins.StreamSegment{StreamID: "s-1", Seq: seq, Accumulated: accumulated}
}

func streamInput(mode policy.Mode, set map[string]any, event *metrics.EventContext) appplugins.ExecInput {
	in := execInput(policy.StagePreResponse, mode, set, nil, nil)
	in.Event = event
	return in
}

func newEvent() (*metrics.EventContext, *trace.Span) {
	tr := trace.New("", trace.Metadata{})
	span := tr.StartSpan(trace.SpanPlugin, PluginName)
	return metrics.NewEventContext(span), span
}

func TestStreamSettingsOptIn(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	cases := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{"absent block", bufferedSettings(), false},
		{"enabled", streamSettings(nil), true},
		{
			"explicitly disabled",
			streamSettings(map[string]any{"enabled": false}),
			false,
		},
		{
			"enabled but the settings do not parse",
			map[string]any{"streaming": map[string]any{"enabled": true}},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _ := p.StreamSettings(tc.settings)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestStreamSettingsDefaultsToFailClosed(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	on, opts := p.StreamSettings(streamSettings(nil))

	require.True(t, on)
	assert.Equal(t, "fail_closed", opts.OnError,
		"the buffered leg fails closed when ApplyGuardrail is unreachable")
}

func TestInspectSegmentAllowsCleanText(t *testing.T) {
	t.Parallel()
	g := allowing()
	p := streamPlugin(t, g)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(1, "a clean paragraph"))

	require.NoError(t, err)
	assert.False(t, got.Block)
	assert.False(t, got.HasTransform)
	assert.Equal(t, 1, g.calls)
}

// The guardrail decides over a whole turn, so a block inspected on its own
// loses what made it a violation.
func TestInspectSegmentSendsTheAccumulatedPrefix(t *testing.T) {
	t.Parallel()
	g := allowing()
	p := streamPlugin(t, g)

	seg := appplugins.StreamSegment{
		StreamID: "s-1", Seq: 2,
		Text:        "only this delta",
		Accumulated: "everything produced so far",
	}
	_, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), seg)

	require.NoError(t, err)
	require.Len(t, g.inputs, 1)
	assert.Equal(t, "everything produced so far", g.inputs[0])
}

// Bedrock applies a different half of the guardrail configuration to each side,
// so a response evaluated as INPUT is checked against the wrong policies and
// says nothing about it.
func TestInspectSegmentMarksTheTextAsOutput(t *testing.T) {
	t.Parallel()
	g := allowing()
	p := streamPlugin(t, g)

	_, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(1, "assistant text"))

	require.NoError(t, err)
	require.Len(t, g.sources, 1)
	assert.Equal(t, types.GuardrailContentSourceOutput, g.sources[0])
}

func TestInspectSegmentBlocks(t *testing.T) {
	t.Parallel()
	p := streamPlugin(t, intervening(blockingOutput()))

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(3, "hateful output"))

	require.NoError(t, err)
	assert.True(t, got.Block)
	assert.Equal(t, typeGuardrailBlocked, got.Type)
	assert.Equal(t, defaultBlockMessage, got.Message)
	assert.False(t, got.HasTransform)
}

// Transformed replaces the whole of seg.Accumulated, and ApplyGuardrail returns
// the masked form of exactly the text it was handed, so the two line up without
// splicing per-block fragments.
func TestInspectSegmentAnonymisesAsATransform(t *testing.T) {
	t.Parallel()
	p := streamPlugin(t, intervening(anonymisingOutput("write to {EMAIL} for details")))

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil),
		segment(2, "write to a@b.com for details"))

	require.NoError(t, err)
	assert.False(t, got.Block, "a maskable finding must not end the stream")
	assert.True(t, got.HasTransform)
	assert.Equal(t, "write to {EMAIL} for details", got.Transformed)
}

// Releasing the unmasked text is the one outcome the policy ruled out, and the
// buffered leg blocks for the same reason.
func TestInspectSegmentCutsWhenAnonymisationProducedNothing(t *testing.T) {
	t.Parallel()
	p := streamPlugin(t, intervening(anonymisingOutput("")))

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil),
		segment(2, "write to a@b.com for details"))

	require.NoError(t, err)
	assert.True(t, got.Block)
	assert.False(t, got.HasTransform, "there is nothing to transform with")
	assert.Equal(t, anonymizeDegradedMessage, got.Message)
}

func TestInspectSegmentReturnsTheCallFailure(t *testing.T) {
	t.Parallel()
	boom := errors.New("bedrock is down")
	p := streamPlugin(t, &scriptedGuardrail{
		apply: func(*bedrockruntime.ApplyGuardrailInput) (*bedrockruntime.ApplyGuardrailOutput, error) {
			return nil, boom
		},
	})

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(5, "some text"))

	require.Error(t, err)
	assert.Nil(t, got, "a failure must not be reported as a clean allow")
	assert.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "block 5")
}

func TestInspectSegmentIsInertWithoutTheOptIn(t *testing.T) {
	t.Parallel()
	g := intervening(blockingOutput())
	p := streamPlugin(t, g)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, bufferedSettings(), nil), segment(1, "hateful output"))

	require.NoError(t, err)
	assert.False(t, got.Block)
	assert.Zero(t, g.calls, "a policy that did not opt in must cost no call")
}

func TestInspectSegmentSkipsEmptyText(t *testing.T) {
	t.Parallel()
	g := intervening(blockingOutput())
	p := streamPlugin(t, g)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(1, "  \n "))

	require.NoError(t, err)
	assert.False(t, got.Block)
	assert.Zero(t, g.calls)
}

func TestClosingSegmentPublishesTheStreamAccount(t *testing.T) {
	t.Parallel()
	g := allowing()
	p := streamPlugin(t, g)
	event, span := newEvent()

	_, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), event),
		appplugins.StreamSegment{
			StreamID: "s-1", Closing: true,
			Report: appplugins.StreamReport{
				Evals: 4, GuardCalls: 4, CutAtEval: 2, CutOffsetChars: 310,
				GuardLatency: 900 * time.Millisecond,
			},
		})

	require.NoError(t, err)
	assert.Zero(t, g.calls, "the closing segment asks for no verdict")

	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	require.NotNil(t, data.Streaming)
	assert.True(t, data.Streaming.Enabled)
	assert.Equal(t, 4, data.Streaming.EvalsTotal)
	assert.Equal(t, 2, data.Streaming.CutAtEval)
	assert.Equal(t, 310, data.Streaming.CutOffsetChars)
	assert.Equal(t, int64(900), data.Streaming.GuardLatencyMsTotal)
	assert.Equal(t, decisionBlocked, data.Decision)
	assert.Equal(t, "gr-1", data.GuardrailID)
}

func TestClosingSegmentDecisionFollowsTheOutcome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		report   appplugins.StreamReport
		findings []appplugins.StreamFinding
		want     string
	}{
		{"clean", appplugins.StreamReport{Evals: 3, GuardCalls: 3}, nil, decisionAllowed},
		{
			"reported but not cut",
			appplugins.StreamReport{Evals: 3, GuardCalls: 3},
			[]appplugins.StreamFinding{{Entry: "p", Fingerprint: "abcd"}},
			decisionReported,
		},
		{"cut", appplugins.StreamReport{Evals: 2, CutAtEval: 1}, nil, decisionBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := streamPlugin(t, allowing())
			event, span := newEvent()

			_, err := p.InspectSegment(context.Background(),
				streamInput(policy.ModeEnforce, streamSettings(nil), event),
				appplugins.StreamSegment{
					StreamID: "s-1", Closing: true,
					Report: tc.report, Findings: tc.findings,
				})

			require.NoError(t, err)
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, tc.want, data.Decision)
		})
	}
}

func TestFindingFingerprintsIdentifyTheMatch(t *testing.T) {
	t.Parallel()
	base := &finding{policy: "content", name: "HATE", matchType: "filter", action: "BLOCKED"}

	got := findingFingerprints(policy.ModeObserve, base)
	require.Len(t, got, 1)
	assert.Equal(t, got, findingFingerprints(policy.ModeObserve, base),
		"every field is a configuration label, so the key must not move with the prefix")

	for _, other := range []*finding{
		{policy: "topic", name: "HATE", matchType: "filter", action: "BLOCKED"},
		{policy: "content", name: "VIOLENCE", matchType: "filter", action: "BLOCKED"},
		{policy: "content", name: "HATE", matchType: "word", action: "BLOCKED"},
		{policy: "content", name: "HATE", matchType: "filter", action: "ANONYMIZED"},
	} {
		assert.NotEqual(t, got, findingFingerprints(policy.ModeObserve, other),
			"a different %v must not fold into the same key", other)
	}
}

func TestFindingFingerprintsSkipBlockingModesAndNilFindings(t *testing.T) {
	t.Parallel()
	f := &finding{policy: "content", name: "HATE", matchType: "filter", action: "BLOCKED"}
	assert.Nil(t, findingFingerprints(policy.ModeEnforce, f),
		"a blocking mode stops the stream, so nothing comes back to deduplicate")
	assert.Nil(t, findingFingerprints(policy.ModeObserve, nil))
}
