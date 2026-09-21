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

package plugins

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// streamPlugin is a fakePlugin that implements StreamInspector, so the tests
// cover both sides of the opt-in without touching a real plugin.
type streamPlugin struct {
	fakePlugin
	verdict *SegmentVerdict
	err     error
	seen    []StreamSegment
	inputs  []ExecInput
}

func (p *streamPlugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve, policy.ModeThrottle}
}

func (p *streamPlugin) InspectSegment(_ context.Context, in ExecInput, seg StreamSegment) (*SegmentVerdict, error) {
	p.seen = append(p.seen, seg)
	p.inputs = append(p.inputs, in)
	if p.err != nil {
		return nil, p.err
	}
	return p.verdict, nil
}

// StreamSettings answers from the settings map the way a real plugin does, so
// the plan can tell an enabled policy from a disabled one without knowing any
// plugin's schema.
func (p *streamPlugin) StreamSettings(settings map[string]any) (bool, StreamOptions) {
	enabled, _ := settings["enabled"].(bool)
	if !enabled {
		return false, StreamOptions{}
	}
	var opts StreamOptions
	opts.HeadChars, _ = settings["head_chars"].(int)
	opts.OnError, _ = settings["on_error"].(string)
	return true, opts
}

func newStreamPlugin(name string, verdict *SegmentVerdict) *streamPlugin {
	return &streamPlugin{
		fakePlugin: fakePlugin{
			name:   name,
			stages: []policy.Stage{policy.StagePreResponse},
			result: &Result{StatusCode: 200},
		},
		verdict: verdict,
	}
}

type entrySpec struct {
	slug    string
	mode    policy.Mode
	verdict *SegmentVerdict
}

func streamChain(t *testing.T, specs ...entrySpec) (Executor, []*policy.Policy, map[string]*streamPlugin) {
	t.Helper()
	plugins := make([]Plugin, 0, len(specs))
	inspectors := make(map[string]*streamPlugin, len(specs))
	pols := make([]*policy.Policy, 0, len(specs))
	for i, spec := range specs {
		p := newStreamPlugin(spec.slug, spec.verdict)
		plugins = append(plugins, p)
		inspectors[spec.slug] = p
		pol := policies(t, polSpec{
			slug:     spec.slug,
			enabled:  true,
			priority: (i + 1) * 10,
			stages:   []policy.Stage{policy.StagePreResponse},
		})[0]
		pol.Mode = spec.mode
		pols = append(pols, pol)
	}
	return NewExecutor(newRegistry(t, plugins...), nil), pols, inspectors
}

func segment(seq int, final bool) StreamSegment {
	return StreamSegment{StreamID: "stream-1", Seq: seq, Final: final, Text: "tail", Accumulated: "head tail"}
}

func runSegment(t *testing.T, exec Executor, in StageInput, seg StreamSegment) (*SegmentOutcome, error) {
	t.Helper()
	runner, ok := exec.(*executor)
	require.True(t, ok, "RunStreamSegment lives on the concrete executor, never on the Executor interface")
	return runner.RunStreamSegment(context.Background(), in, seg)
}

func TestStreamInspector_DefaultsToDenyWithoutTheInterface(t *testing.T) {
	plain := &fakePlugin{name: "plain", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{}}
	_, plainOK := streamInspector(plain)
	assert.False(t, plainOK, "a descriptor that does not implement StreamInspector must be denied")
	_, guardOK := streamInspector(newStreamPlugin("guard", nil))
	assert.True(t, guardOK)
}

func TestExecutor_RunStreamSegment_EmptyChain(t *testing.T) {
	out, err := runSegment(t, NewExecutor(NewRegistry(), nil), StageInput{
		Stage:    policy.StagePreResponse,
		Response: &infracontext.ResponseContext{},
	}, segment(0, false))

	require.NoError(t, err)
	require.NotNil(t, out)
	assert.False(t, out.Block)
	assert.Empty(t, out.Fingerprints)
}

func TestExecutor_RunStreamSegment_FiltersTheChain(t *testing.T) {
	inspector := newStreamPlugin("guard", &SegmentVerdict{Fingerprints: []string{"f1"}})
	plain := &fakePlugin{name: "plain", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{StatusCode: 200}}
	preRequestOnly := newStreamPlugin("early", &SegmentVerdict{Block: true, Type: "pii"})
	preRequestOnly.stages = []policy.Stage{policy.StagePreRequest}
	exec := NewExecutor(newRegistry(t, inspector, plain, preRequestOnly), nil)

	pols := policies(t,
		polSpec{slug: "guard", enabled: true, priority: 10, stages: []policy.Stage{policy.StagePreResponse}},
		polSpec{slug: "plain", enabled: true, priority: 20, stages: []policy.Stage{policy.StagePreResponse}},
		polSpec{slug: "early", enabled: true, priority: 30, stages: []policy.Stage{policy.StagePreRequest}},
	)

	out, err := runSegment(t, exec, StageInput{
		Stage:    policy.StagePreResponse,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	}, segment(0, false))

	require.NoError(t, err)
	assert.False(t, out.Block, "a plugin that only runs at pre_request is not part of the stream chain")
	assert.Equal(t, []string{"f1"}, out.Fingerprints)
	assert.Len(t, inspector.seen, 1)
	assert.Empty(t, preRequestOnly.seen)
}

func TestExecutor_RunStreamSegment_MergesTheChainVerdicts(t *testing.T) {
	block := func() *SegmentVerdict {
		return &SegmentVerdict{Block: true, Type: "jailbreak", Message: "cut", Fingerprints: []string{"f-block"}}
	}
	mask := func(text, kind string) *SegmentVerdict {
		return &SegmentVerdict{HasTransform: true, Transformed: text, Type: kind}
	}

	tests := []struct {
		name          string
		specs         []entrySpec
		want          SegmentOutcome
		wantConsulted []string
	}{
		{
			name:          "a nil verdict is an allow",
			specs:         []entrySpec{{slug: "guard", mode: policy.ModeEnforce}},
			wantConsulted: []string{"guard"},
		},
		{
			name:          "enforce blocks",
			specs:         []entrySpec{{slug: "guard", mode: policy.ModeEnforce, verdict: block()}},
			want:          SegmentOutcome{Block: true, Type: "jailbreak", Message: "cut", Fingerprints: []string{"f-block"}},
			wantConsulted: []string{"guard"},
		},
		{
			name:          "throttle blocks",
			specs:         []entrySpec{{slug: "guard", mode: policy.ModeThrottle, verdict: block()}},
			want:          SegmentOutcome{Block: true, Type: "jailbreak", Message: "cut", Fingerprints: []string{"f-block"}},
			wantConsulted: []string{"guard"},
		},
		{
			name:          "observe reports but never blocks",
			specs:         []entrySpec{{slug: "guard", mode: policy.ModeObserve, verdict: block()}},
			want:          SegmentOutcome{Type: "jailbreak", Message: "cut", Fingerprints: []string{"f-block"}},
			wantConsulted: []string{"guard"},
		},
		{
			name:          "observe never rewrites held text",
			specs:         []entrySpec{{slug: "guard", mode: policy.ModeObserve, verdict: mask("masked", "pii")}},
			want:          SegmentOutcome{Type: "pii"},
			wantConsulted: []string{"guard"},
		},
		{
			name:          "enforce rewrites held text",
			specs:         []entrySpec{{slug: "guard", mode: policy.ModeEnforce, verdict: mask("masked", "pii")}},
			want:          SegmentOutcome{HasTransform: true, Transformed: "masked", Type: "pii"},
			wantConsulted: []string{"guard"},
		},
		{
			name: "block beats transform and stops the chain",
			specs: []entrySpec{
				{slug: "a_masker", mode: policy.ModeEnforce, verdict: mask("masked", "pii")},
				{slug: "b_blocker", mode: policy.ModeEnforce, verdict: block()},
				{slug: "c_last", mode: policy.ModeEnforce, verdict: &SegmentVerdict{Fingerprints: []string{"never"}}},
			},
			want:          SegmentOutcome{Block: true, Type: "jailbreak", Message: "cut", Fingerprints: []string{"f-block"}},
			wantConsulted: []string{"a_masker", "b_blocker"},
		},
		{
			name: "transform beats allow and the first one in chain order wins",
			specs: []entrySpec{
				{slug: "a_allow", mode: policy.ModeEnforce, verdict: &SegmentVerdict{Fingerprints: []string{"f-allow"}}},
				{slug: "b_first", mode: policy.ModeEnforce, verdict: mask("first", "pii")},
				{slug: "c_second", mode: policy.ModeEnforce, verdict: mask("second", "secret")},
			},
			want:          SegmentOutcome{HasTransform: true, Transformed: "first", Type: "pii", Fingerprints: []string{"f-allow"}},
			wantConsulted: []string{"a_allow", "b_first", "c_second"},
		},
		{
			name: "an observe-mode block never stops the enforcing entry behind it",
			specs: []entrySpec{
				{slug: "a_observer", mode: policy.ModeObserve, verdict: block()},
				{slug: "b_enforcer", mode: policy.ModeEnforce, verdict: &SegmentVerdict{Fingerprints: []string{"f-enforce"}}},
			},
			want: SegmentOutcome{
				Type:         "jailbreak",
				Message:      "cut",
				Fingerprints: []string{"f-block", "f-enforce"},
			},
			wantConsulted: []string{"a_observer", "b_enforcer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exec, pols, inspectors := streamChain(t, tt.specs...)

			out, err := runSegment(t, exec, StageInput{
				Stage:    policy.StagePreResponse,
				Policies: pols,
				Response: &infracontext.ResponseContext{},
			}, segment(1, false))

			require.NoError(t, err)
			assert.Equal(t, tt.want.Block, out.Block)
			assert.Equal(t, tt.want.HasTransform, out.HasTransform)
			assert.Equal(t, tt.want.Transformed, out.Transformed)
			assert.Equal(t, tt.want.Type, out.Type)
			assert.Equal(t, tt.want.Message, out.Message)
			assert.Equal(t, tt.want.Fingerprints, out.Fingerprints)

			consulted := make([]string, 0, len(tt.specs))
			for _, spec := range tt.specs {
				if len(inspectors[spec.slug].seen) > 0 {
					consulted = append(consulted, spec.slug)
				}
			}
			assert.Equal(t, tt.wantConsulted, consulted)
		})
	}
}

func TestExecutor_RunStreamSegment_HandsTheEntryToTheInspector(t *testing.T) {
	exec, pols, inspectors := streamChain(t, entrySpec{slug: "guard", mode: policy.ModeObserve})

	_, err := runSegment(t, exec, StageInput{
		Stage:    policy.StagePreResponse,
		Policies: pols,
		Request:  &infracontext.RequestContext{GatewayID: "gw-1", ConsumerID: "c-1"},
		Response: &infracontext.ResponseContext{},
	}, segment(3, true))

	require.NoError(t, err)
	guard := inspectors["guard"]
	require.Len(t, guard.inputs, 1)
	assert.Equal(t, policy.StagePreResponse, guard.inputs[0].Stage)
	assert.Equal(t, policy.ModeObserve, guard.inputs[0].Mode)
	assert.Equal(t, "guard", guard.inputs[0].Config.Slug)
	assert.Equal(t, "c-1", guard.inputs[0].Scope.ConsumerID)
	require.Len(t, guard.seen, 1)
	assert.Equal(t, 3, guard.seen[0].Seq)
	assert.True(t, guard.seen[0].Final)
}

func TestExecutor_RunStreamSegment_WrapsTheInspectorError(t *testing.T) {
	sentinel := errors.New("guard unreachable")
	exec, pols, inspectors := streamChain(t, entrySpec{slug: "guard", mode: policy.ModeEnforce})
	inspectors["guard"].err = sentinel

	out, err := runSegment(t, exec, StageInput{
		Stage:    policy.StagePreResponse,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	}, segment(4, false))

	require.ErrorIs(t, err, sentinel)
	assert.Nil(t, out, "the caller applies its own on_error policy; a partial outcome would hide the failure")
	assert.Contains(t, err.Error(), "guard")
}

func TestExecutor_RunStreamSegment_OpensOneSpanPerStream(t *testing.T) {
	exec, pols, _ := streamChain(t, entrySpec{slug: "guard", mode: policy.ModeObserve})
	runner, ok := exec.(*executor)
	require.True(t, ok)
	in := StageInput{Stage: policy.StagePreResponse, Policies: pols, Response: &infracontext.ResponseContext{}}

	rt := trace.New("t", trace.Metadata{})
	ctx, publish := NewStreamSpanContext(trace.NewContext(context.Background(), rt))
	defer publish()
	for seq := range 3 {
		_, err := runner.RunStreamSegment(ctx, in, segment(seq, seq == 2))
		require.NoError(t, err)
	}

	spans := rt.Spans()
	require.Len(t, spans, 1, "three segments of one stream must share a single plugin span")
	assert.Equal(t, trace.SpanPlugin, spans[0].Type)
	assert.Equal(t, "guard", spans[0].Name)
	require.NotNil(t, spans[0].Plugin)
	assert.Equal(t, string(policy.StagePreResponse), spans[0].Plugin.Stage)
	assert.Equal(t, string(policy.ModeObserve), spans[0].Plugin.Mode)
	assert.False(t, spans[0].EndedAt().IsZero(), "the final segment ends the stream span")

	twoExec, twoPols, _ := streamChain(t,
		entrySpec{slug: "guard_a", mode: policy.ModeObserve},
		entrySpec{slug: "guard_b", mode: policy.ModeObserve},
	)
	twoRunner, ok := twoExec.(*executor)
	require.True(t, ok)
	twoRT := trace.New("t", trace.Metadata{})
	twoCtx, twoPublish := NewStreamSpanContext(trace.NewContext(context.Background(), twoRT))
	defer twoPublish()
	for seq := range 2 {
		_, err := twoRunner.RunStreamSegment(twoCtx, StageInput{
			Stage:    policy.StagePreResponse,
			Policies: twoPols,
			Response: &infracontext.ResponseContext{},
		}, segment(seq, seq == 1))
		require.NoError(t, err)
	}
	twoSpans := twoRT.Spans()
	require.Len(t, twoSpans, 2, "two inspecting policies share the stream but never share a span")
	assert.ElementsMatch(t, []string{"guard_a", "guard_b"}, []string{twoSpans[0].Name, twoSpans[1].Name},
		"one span per policy id, and each policy carries its own plugin")

	bare := trace.New("t", trace.Metadata{})
	_, err := runner.RunStreamSegment(trace.NewContext(context.Background(), bare), in, segment(0, false))
	require.NoError(t, err)
	assert.Empty(t, bare.Spans(), "without a stream span context no span is opened per segment")
}

func TestExecutor_RunStreamSegment_UsesThePreResponsePlan(t *testing.T) {
	exec, pols, inspectors := streamChain(t, entrySpec{
		slug:    "guard",
		mode:    policy.ModeEnforce,
		verdict: &SegmentVerdict{Fingerprints: []string{"f1"}},
	})
	runner, ok := exec.(*executor)
	require.True(t, ok)

	out, err := runSegment(t, exec, StageInput{
		Stage:    policy.StagePostResponse,
		Plan:     NewStagePlan(runner.registry, pols, nil),
		Response: &infracontext.ResponseContext{},
	}, segment(0, false))

	require.NoError(t, err)
	assert.Equal(t, []string{"f1"}, out.Fingerprints, "the stream chain is the pre_response chain whatever StageInput.Stage says")
	assert.Len(t, inspectors["guard"].seen, 1)
}
