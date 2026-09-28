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
	"time"

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
	verdict   *SegmentVerdict
	err       error
	closedErr error
	seen      []StreamSegment
	inputs    []ExecInput
	clock     *testClock
	spend     time.Duration
}

// testClock replaces the executor's wall clock so a per-entry latency assertion
// states an exact number rather than a tolerance. Every inspector in a chain
// shares one instance, which is what makes the shares comparable.
type testClock struct{ at time.Time }

func (c *testClock) now() time.Time { return c.at }

func (c *testClock) advance(d time.Duration) { c.at = c.at.Add(d) }

func (p *streamPlugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve, policy.ModeThrottle}
}

func (p *streamPlugin) InspectSegment(_ context.Context, in ExecInput, seg StreamSegment) (*SegmentVerdict, error) {
	p.seen = append(p.seen, seg)
	p.inputs = append(p.inputs, in)
	if p.clock != nil {
		p.clock.advance(p.spend)
	}
	if seg.Closing {
		// What the trustguard inspector does with the report it is handed, so
		// the executor's attribution can be asserted where it actually lands.
		in.Event.SetSLatency(seg.Report.GuardLatency)
		return nil, p.closedErr
	}
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
	spend   time.Duration
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

// streamChainWithClock is streamChain with the executor's wall clock replaced
// and a fixed cost per inspector call, so the shares a chain is charged come out
// as exact numbers rather than as tolerances.
func streamChainWithClock(
	t *testing.T,
	clock *testClock,
	specs ...entrySpec,
) (*executor, []*policy.Policy, map[string]*streamPlugin) {
	t.Helper()
	exec, pols, inspectors := streamChain(t, specs...)
	runner, ok := exec.(*executor)
	require.True(t, ok)
	runner.now = clock.now
	for _, spec := range specs {
		inspectors[spec.slug].clock = clock
		inspectors[spec.slug].spend = spec.spend
	}
	return runner, pols, inspectors
}

// fingerprints drops the entry the executor tagged each key with, so a merge
// assertion states the keys in chain order. The tags are asserted where
// attribution is what is under test.
func fingerprints(findings []StreamFinding) []string {
	if len(findings) == 0 {
		return nil
	}
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Fingerprint)
	}
	return out
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
	assert.Equal(t, []string{"f1"}, fingerprints(out.Fingerprints))
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
		wantPrints    []string
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
			want:          SegmentOutcome{Block: true, Type: "jailbreak", Message: "cut"},
			wantPrints:    []string{"f-block"},
			wantConsulted: []string{"guard"},
		},
		{
			name:          "throttle blocks",
			specs:         []entrySpec{{slug: "guard", mode: policy.ModeThrottle, verdict: block()}},
			want:          SegmentOutcome{Block: true, Type: "jailbreak", Message: "cut"},
			wantPrints:    []string{"f-block"},
			wantConsulted: []string{"guard"},
		},
		{
			name:          "observe reports but never blocks",
			specs:         []entrySpec{{slug: "guard", mode: policy.ModeObserve, verdict: block()}},
			want:          SegmentOutcome{Type: "jailbreak", Message: "cut"},
			wantPrints:    []string{"f-block"},
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
			want:          SegmentOutcome{Block: true, Type: "jailbreak", Message: "cut"},
			wantPrints:    []string{"f-block"},
			wantConsulted: []string{"a_masker", "b_blocker"},
		},
		{
			name: "transform beats allow and the first one in chain order wins",
			specs: []entrySpec{
				{slug: "a_allow", mode: policy.ModeEnforce, verdict: &SegmentVerdict{Fingerprints: []string{"f-allow"}}},
				{slug: "b_first", mode: policy.ModeEnforce, verdict: mask("first", "pii")},
				{slug: "c_second", mode: policy.ModeEnforce, verdict: mask("second", "secret")},
			},
			want:          SegmentOutcome{HasTransform: true, Transformed: "first", Type: "pii"},
			wantPrints:    []string{"f-allow"},
			wantConsulted: []string{"a_allow", "b_first", "c_second"},
		},
		{
			name: "an observe-mode block never stops the enforcing entry behind it",
			specs: []entrySpec{
				{slug: "a_observer", mode: policy.ModeObserve, verdict: block()},
				{slug: "b_enforcer", mode: policy.ModeEnforce, verdict: &SegmentVerdict{Fingerprints: []string{"f-enforce"}}},
			},
			want:          SegmentOutcome{Type: "jailbreak", Message: "cut"},
			wantPrints:    []string{"f-block", "f-enforce"},
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
			assert.Equal(t, tt.wantPrints, fingerprints(out.Fingerprints))

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

// The guard folds one set for a chain two policies sit in, so the tag the
// executor writes is what keeps the closing segment from handing either of them
// the other's findings. A plugin answers for itself and never says so.
func TestExecutor_RunStreamSegment_NarrowsTheStreamsFindingsToTheEntry(t *testing.T) {
	exec, pols, inspectors := streamChain(t,
		entrySpec{slug: "a_guard", mode: policy.ModeObserve, verdict: &SegmentVerdict{Fingerprints: []string{"f-a"}}},
		entrySpec{slug: "b_guard", mode: policy.ModeObserve, verdict: &SegmentVerdict{Fingerprints: []string{"f-b"}}},
	)
	in := StageInput{Stage: policy.StagePreResponse, Policies: pols, Response: &infracontext.ResponseContext{}}

	out, err := runSegment(t, exec, in, segment(1, false))
	require.NoError(t, err)
	assert.Equal(t, []StreamFinding{
		{Entry: pols[0].ID.String(), Fingerprint: "f-a"},
		{Entry: pols[1].ID.String(), Fingerprint: "f-b"},
	}, out.Fingerprints, "the entry is the executor's to record; the plugin returned a bare key")

	_, err = runSegment(t, exec, in, StreamSegment{
		StreamID: "stream-1", Seq: 2, Closing: true, Findings: out.Fingerprints,
	})
	require.NoError(t, err)

	assert.Equal(t, []StreamFinding{{Entry: pols[0].ID.String(), Fingerprint: "f-a"}},
		lastSeen(t, inspectors["a_guard"]).Findings)
	assert.Equal(t, []StreamFinding{{Entry: pols[1].ID.String(), Fingerprint: "f-b"}},
		lastSeen(t, inspectors["b_guard"]).Findings)
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
	closing := segment(3, false)
	closing.Closing = true
	_, err := runner.RunStreamSegment(ctx, in, closing)
	require.NoError(t, err)

	spans := rt.Spans()
	require.Len(t, spans, 1, "three segments of one stream must share a single plugin span")
	assert.Equal(t, trace.SpanPlugin, spans[0].Type)
	assert.Equal(t, "guard", spans[0].Name)
	require.NotNil(t, spans[0].Plugin)
	assert.Equal(t, string(policy.StagePreResponse), spans[0].Plugin.Stage)
	assert.Equal(t, string(policy.ModeObserve), spans[0].Plugin.Mode)
	assert.False(t, spans[0].EndedAt().IsZero(), "the closing segment ends the stream span")

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
	_, err = runner.RunStreamSegment(trace.NewContext(context.Background(), bare), in, segment(0, false))
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
	assert.Equal(t, []string{"f1"}, fingerprints(out.Fingerprints),
		"the stream chain is the pre_response chain whatever StageInput.Stage says")
	assert.Len(t, inspectors["guard"].seen, 1)
}

// chainReport is the guard's account of a stream that cost three blocks and
// 120ms of chain time, of which the enforcing entry cut on the third.
func chainReport() StreamReport {
	return StreamReport{
		Evals:           3,
		GuardCalls:      3,
		GuardLatency:    120 * time.Millisecond,
		GuardLatencyMax: 40 * time.Millisecond,
		AddedLatency:    200 * time.Millisecond,
		CutAtEval:       3,
		CutOffsetChars:  42,
	}
}

// TestExecutor_RunStreamSegment_ChargesTheHoldOncePerChain is the N>1 case the
// per-entry split exists for. The guard measures the chain as one call and hands
// the same account to every inspector; written unchanged onto every span it
// would be summed once per streaming policy by foldPluginSpans, so two policies
// would charge the policy chain twice the hold and drive gateway_ms to zero.
func TestExecutor_RunStreamSegment_ChargesTheHoldOncePerChain(t *testing.T) {
	clock := &testClock{at: time.UnixMilli(1_000_000)}
	runner, pols, inspectors := streamChainWithClock(t, clock,
		entrySpec{slug: "watcher", mode: policy.ModeObserve, spend: 30 * time.Millisecond},
		entrySpec{slug: "enforcer", mode: policy.ModeEnforce, spend: 10 * time.Millisecond},
	)
	in := StageInput{Stage: policy.StagePreResponse, Policies: pols, Response: &infracontext.ResponseContext{}}

	rt := trace.New("t", trace.Metadata{})
	ctx, publish := NewStreamSpanContext(trace.NewContext(context.Background(), rt))
	defer publish()

	for seq := 1; seq <= 2; seq++ {
		_, err := runner.RunStreamSegment(ctx, in, segment(seq, false))
		require.NoError(t, err)
	}
	inspectors["enforcer"].verdict = &SegmentVerdict{Block: true, Type: "trustguard_blocked", Message: "no"}
	out, err := runner.RunStreamSegment(ctx, in, segment(3, false))
	require.NoError(t, err)
	require.True(t, out.Block)

	closing := StreamSegment{StreamID: "stream-1", Seq: 3, Closing: true, Report: chainReport()}
	_, err = runner.RunStreamSegment(ctx, in, closing)
	require.NoError(t, err)

	watcher := lastSeen(t, inspectors["watcher"])
	enforcer := lastSeen(t, inspectors["enforcer"])
	require.True(t, watcher.Closing)
	require.True(t, enforcer.Closing)

	assert.Equal(t, 90*time.Millisecond, watcher.Report.GuardLatency,
		"the observing entry is charged the three calls it made, not the chain's")
	assert.Equal(t, 30*time.Millisecond, enforcer.Report.GuardLatency)
	assert.Equal(t, chainReport().GuardLatency, watcher.Report.GuardLatency+enforcer.Report.GuardLatency,
		"the shares must add up to the hold the guard measured, exactly once")

	assert.Zero(t, watcher.Report.CutAtEval,
		"an observe-mode entry must not report the cut an enforcing entry beside it made")
	assert.Zero(t, watcher.Report.CutOffsetChars)
	assert.Equal(t, 3, enforcer.Report.CutAtEval)
	assert.Equal(t, 42, enforcer.Report.CutOffsetChars)

	assert.Equal(t, 3, watcher.Report.Evals, "what the stream cost reaches every entry unchanged")
	assert.Equal(t, 200*time.Millisecond, watcher.Report.AddedLatency)
	assert.False(t, watcher.ReportsStream,
		"a per-response instrument recorded by every entry counts one response once per policy")
	assert.True(t, enforcer.ReportsStream, "the entry that cut speaks for the stream")

	spans := rt.Spans()
	require.Len(t, spans, 2)
	var total time.Duration
	for _, span := range spans {
		total += span.Latency()
		assert.False(t, span.EndedAt().IsZero(), "the closing segment ends every span in the chain")
	}
	assert.Equal(t, chainReport().GuardLatency, total,
		"foldPluginSpans sums these; the sum is one hold, never one per policy")
}

func lastSeen(t *testing.T, p *streamPlugin) StreamSegment {
	t.Helper()
	require.NotEmpty(t, p.seen)
	return p.seen[len(p.seen)-1]
}

// TestExecutor_RunStreamSegment_ClosingSurvivesAnInspectorError pins the tail of
// the chain: a closing segment asks for no verdict, so one inspector failing on
// it must not cost the ones after it the only point at which they can publish,
// nor leave their spans to end on the default wall clock.
func TestExecutor_RunStreamSegment_ClosingSurvivesAnInspectorError(t *testing.T) {
	sentinel := errors.New("aggregate rejected")
	exec, pols, inspectors := streamChain(t,
		entrySpec{slug: "first", mode: policy.ModeEnforce},
		entrySpec{slug: "second", mode: policy.ModeEnforce},
		entrySpec{slug: "third", mode: policy.ModeObserve},
	)
	runner, ok := exec.(*executor)
	require.True(t, ok)
	inspectors["second"].closedErr = sentinel
	in := StageInput{Stage: policy.StagePreResponse, Policies: pols, Response: &infracontext.ResponseContext{}}

	rt := trace.New("t", trace.Metadata{})
	ctx, publish := NewStreamSpanContext(trace.NewContext(context.Background(), rt))
	defer publish()

	_, err := runner.RunStreamSegment(ctx, in, segment(1, false))
	require.NoError(t, err)
	_, err = runner.RunStreamSegment(ctx, in, StreamSegment{StreamID: "stream-1", Seq: 1, Closing: true})
	require.NoError(t, err, "a closing segment reads no verdict, so it cannot fail the chain")

	for _, slug := range []string{"first", "second", "third"} {
		assert.True(t, lastSeen(t, inspectors[slug]).Closing, "%s never got its closing segment", slug)
	}
	spans := rt.Spans()
	require.Len(t, spans, 3)
	errored := 0
	for _, span := range spans {
		assert.False(t, span.EndedAt().IsZero(), "%s ended on the default wall clock", span.Name)
		if span.Error() != "" {
			errored++
			assert.Equal(t, "second", span.Name, "the error belongs to the inspector that raised it")
		}
	}
	assert.Equal(t, 1, errored, "the failure is recorded, on one span")
}

func TestExecutor_RunStreamSegment_ClosingIsNeverFinal(t *testing.T) {
	exec, pols, inspectors := streamChain(t, entrySpec{slug: "guard", mode: policy.ModeEnforce})

	_, err := runSegment(t, exec, StageInput{
		Stage:    policy.StagePreResponse,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	}, StreamSegment{StreamID: "stream-1", Seq: 7, Final: true, Closing: true})

	require.NoError(t, err)
	seen := lastSeen(t, inspectors["guard"])
	assert.True(t, seen.Closing)
	assert.False(t, seen.Final,
		"the span lifecycle keys on Closing alone; a segment carrying no text is not the final block")
}
