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
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orderStub is a stream inspector whose verdict is a function of the segment it
// is handed, so a test can assert what each entry saw and not only what it
// answered. calls is a shared log: the order entries were consulted in.
type orderStub struct {
	*streamPlugin
	fn    func(StreamSegment) *SegmentVerdict
	reads bool
	log   *[]string
}

func (o *orderStub) InspectSegment(_ context.Context, _ ExecInput, seg StreamSegment) (*SegmentVerdict, error) {
	o.seen = append(o.seen, seg)
	if seg.Closing {
		return nil, nil
	}
	*o.log = append(*o.log, o.name)
	if o.fn == nil {
		return nil, nil
	}
	return o.fn(seg), nil
}

func (o *orderStub) ReadsContent() bool { return o.reads }

type orderSpec struct {
	slug     string
	priority int
	mode     policy.Mode
	rewrites bool
	reads    bool
	fn       func(StreamSegment) *SegmentVerdict
}

// replaceWith masks every occurrence of secret, the way regex_replace does over
// seg.Accumulated, and answers allow when nothing matched.
func replaceWith(secret, mask string) func(StreamSegment) *SegmentVerdict {
	return func(seg StreamSegment) *SegmentVerdict {
		if !strings.Contains(seg.Accumulated, secret) {
			return nil
		}
		return &SegmentVerdict{HasTransform: true, Transformed: strings.ReplaceAll(seg.Accumulated, secret, mask)}
	}
}

func orderChain(t *testing.T, specs ...orderSpec) (*executor, []*policy.Policy, map[string]*orderStub, *[]string) {
	t.Helper()
	log := &[]string{}
	stubs := make(map[string]*orderStub, len(specs))
	plugins := make([]Plugin, 0, len(specs))
	pols := make([]*policy.Policy, 0, len(specs))
	for _, spec := range specs {
		sp := newStreamPlugin(spec.slug, nil)
		sp.mutResp = spec.rewrites
		stub := &orderStub{streamPlugin: sp, fn: spec.fn, reads: spec.reads, log: log}
		stubs[spec.slug] = stub
		plugins = append(plugins, stub)
		pol := policies(t, polSpec{
			slug:     spec.slug,
			enabled:  true,
			priority: spec.priority,
			parallel: true,
			stages:   []policy.Stage{policy.StagePreResponse},
		})[0]
		pol.Mode = spec.mode
		pols = append(pols, pol)
	}
	exec, ok := NewExecutor(newRegistry(t, plugins...), nil).(*executor)
	require.True(t, ok)
	return exec, pols, stubs, log
}

func runOrder(t *testing.T, exec *executor, pols []*policy.Policy, seg StreamSegment) *SegmentOutcome {
	t.Helper()
	out, err := exec.RunStreamSegment(context.Background(), StageInput{
		Stage:    policy.StagePreResponse,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	}, seg)
	require.NoError(t, err)
	return out
}

func rawSegment() StreamSegment {
	return StreamSegment{StreamID: "s", Seq: 1, Text: " 4111", Accumulated: "card 4111"}
}

func TestRunStreamSegment_ReaderSeesTheMaskedSegment(t *testing.T) {
	t.Parallel()
	// The reader's slug sorts before the rewriter's, so on the old order it
	// inspected the raw card number.
	exec, pols, stubs, log := orderChain(t,
		orderSpec{slug: "a_moderation", priority: 10, mode: policy.ModeEnforce, reads: true},
		orderSpec{slug: "z_masker", priority: 10, mode: policy.ModeEnforce, rewrites: true, fn: replaceWith("4111", "****")},
	)

	out := runOrder(t, exec, pols, rawSegment())

	assert.Equal(t, []string{"z_masker", "a_moderation"}, *log)
	require.Len(t, stubs["a_moderation"].seen, 1)
	assert.Equal(t, "card ****", stubs["a_moderation"].seen[0].Accumulated)
	assert.Equal(t, " ****", stubs["a_moderation"].seen[0].Text)
	assert.True(t, out.HasTransform)
	assert.Equal(t, "card ****", out.Transformed)
}

func TestRunStreamSegment_TwoRewritersCompose(t *testing.T) {
	t.Parallel()
	exec, pols, stubs, _ := orderChain(t,
		orderSpec{slug: "a_first", priority: 10, mode: policy.ModeEnforce, rewrites: true, fn: replaceWith("4111", "****")},
		orderSpec{slug: "b_second", priority: 10, mode: policy.ModeEnforce, rewrites: true, fn: replaceWith("card", "CARD")},
	)

	out := runOrder(t, exec, pols, rawSegment())

	assert.Equal(t, "card ****", stubs["b_second"].seen[0].Accumulated, "the second rewriter transforms the first's output")
	assert.True(t, out.HasTransform)
	assert.Equal(t, "CARD ****", out.Transformed, "the final transform carries both masks")
}

func TestRunStreamSegment_ObserveTransformIsNotHandedOn(t *testing.T) {
	t.Parallel()
	// An observe rewriter's transform is never applied to the client, so the
	// reader must judge the text the client will actually receive.
	exec, pols, stubs, _ := orderChain(t,
		orderSpec{slug: "a_observer", priority: 10, mode: policy.ModeObserve, rewrites: true, fn: replaceWith("4111", "****")},
		orderSpec{slug: "b_moderation", priority: 10, mode: policy.ModeEnforce, reads: true},
	)

	out := runOrder(t, exec, pols, rawSegment())

	assert.Equal(t, "card 4111", stubs["b_moderation"].seen[0].Accumulated)
	assert.False(t, out.HasTransform)
}

func TestRunStreamSegment_BlockAfterMaskStopsTheChain(t *testing.T) {
	t.Parallel()
	exec, pols, stubs, _ := orderChain(t,
		orderSpec{slug: "a_masker", priority: 10, mode: policy.ModeEnforce, rewrites: true, fn: replaceWith("4111", "****")},
		orderSpec{slug: "b_moderation", priority: 10, mode: policy.ModeEnforce, reads: true,
			fn: func(StreamSegment) *SegmentVerdict { return &SegmentVerdict{Block: true, Type: "flagged"} }},
		orderSpec{slug: "c_after", priority: 20, mode: policy.ModeEnforce},
	)

	out := runOrder(t, exec, pols, rawSegment())

	assert.True(t, out.Block)
	assert.False(t, out.HasTransform)
	assert.Empty(t, stubs["c_after"].seen)
}

func TestRunStreamSegment_OrderingRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		specs []orderSpec
		want  []string
	}{
		{
			name: "a different priority is never crossed",
			specs: []orderSpec{
				{slug: "a_moderation", priority: 10, mode: policy.ModeEnforce, reads: true},
				{slug: "z_masker", priority: 20, mode: policy.ModeEnforce, rewrites: true},
			},
			want: []string{"a_moderation", "z_masker"},
		},
		{
			name: "a neutral inspector keeps its place among the rewriters",
			specs: []orderSpec{
				{slug: "a_neutral", priority: 10, mode: policy.ModeEnforce},
				{slug: "b_moderation", priority: 10, mode: policy.ModeEnforce, reads: true},
				{slug: "c_masker", priority: 10, mode: policy.ModeEnforce, rewrites: true},
			},
			want: []string{"a_neutral", "c_masker", "b_moderation"},
		},
		{
			name: "rewriters keep their order and so do readers",
			specs: []orderSpec{
				{slug: "a_reader", priority: 10, mode: policy.ModeEnforce, reads: true},
				{slug: "b_reader", priority: 10, mode: policy.ModeEnforce, reads: true},
				{slug: "c_masker", priority: 10, mode: policy.ModeEnforce, rewrites: true},
				{slug: "d_masker", priority: 10, mode: policy.ModeEnforce, rewrites: true},
			},
			want: []string{"c_masker", "d_masker", "a_reader", "b_reader"},
		},
		{
			name: "a run with no rewriter is left as it was",
			specs: []orderSpec{
				{slug: "a_neutral", priority: 10, mode: policy.ModeEnforce},
				{slug: "b_reader", priority: 10, mode: policy.ModeEnforce, reads: true},
			},
			want: []string{"a_neutral", "b_reader"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exec, pols, _, log := orderChain(t, tt.specs...)
			runOrder(t, exec, pols, rawSegment())
			assert.Equal(t, tt.want, *log)
		})
	}
}

func TestOrderStreamEntries_MatchesThePlanOrder(t *testing.T) {
	t.Parallel()
	_, pols, _, _ := orderChain(t,
		orderSpec{slug: "a_moderation", priority: 10, mode: policy.ModeEnforce, reads: true},
		orderSpec{slug: "z_masker", priority: 10, mode: policy.ModeEnforce, rewrites: true},
	)
	exec, _, _, _ := orderChain(t,
		orderSpec{slug: "a_moderation", priority: 10, mode: policy.ModeEnforce, reads: true},
		orderSpec{slug: "z_masker", priority: 10, mode: policy.ModeEnforce, rewrites: true},
	)
	plan := NewStagePlan(exec.registry, pols, nil)

	got := plan.streamEntriesFor()

	require.Len(t, got, 2)
	assert.Equal(t, "z_masker", got[0].config.Slug)
	assert.Equal(t, "a_moderation", got[1].config.Slug)
}

func TestSegmentAfterTransform_Text(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		seg         StreamSegment
		transformed string
		wantText    string
	}{
		{
			name:        "mask inside the new block",
			seg:         StreamSegment{Text: " 4111", Accumulated: "card 4111"},
			transformed: "card ****",
			wantText:    " ****",
		},
		{
			name:        "mask reaching back before the block keeps the masked prefix",
			seg:         StreamSegment{Text: "11", Accumulated: "card 4111"},
			transformed: "card ****",
			wantText:    "****",
		},
		{
			name:        "multibyte text never splits a rune",
			seg:         StreamSegment{Text: "é", Accumulated: "aé"},
			transformed: "a€",
			wantText:    "€",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := segmentAfterTransform(tt.seg, tt.transformed)
			assert.Equal(t, tt.transformed, got.Accumulated)
			assert.Equal(t, tt.wantText, got.Text)
		})
	}
}
