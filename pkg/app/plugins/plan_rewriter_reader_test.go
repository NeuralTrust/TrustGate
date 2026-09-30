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
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readerPlugin marks a fakePlugin as a content reader (ContentReader opt-in).
type readerPlugin struct{ *fakePlugin }

func (readerPlugin) ReadsContent() bool { return true }

var preReq = []policy.Stage{policy.StagePreRequest}

func pre(slug string, priority int, parallel bool) polSpec {
	return polSpec{slug: slug, enabled: true, priority: priority, parallel: parallel, stages: preReq}
}

// RUN-1693: a rewriter and a reader that share a priority and are both
// parallel must not share a batch, or the reader scores the original text.
func TestExecutor_RunStage_ReaderSeesRewriterOutputAtSamePriority(t *testing.T) {
	// "a_reader" sorts before "z_mask": on develop the reader is batched first
	// with the rewriter and reads the untouched body.
	var seen atomic.Value
	rewriter := &fakePlugin{
		name: "z_mask", stages: preReq, mutReq: true,
		result: &Result{RequestBody: []byte("masked")},
	}
	reader := readerPlugin{&fakePlugin{
		name: "a_reader", stages: preReq,
		execFn: func(in ExecInput) (*Result, error) {
			seen.Store(string(in.Request.Body))
			return &Result{}, nil
		},
	}}
	exec := NewExecutor(newRegistry(t, rewriter, reader), nil)

	req := &infracontext.RequestContext{Body: []byte("original")}
	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: policies(t, pre("a_reader", 0, true), pre("z_mask", 0, true)),
		Request:  req,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, "masked", seen.Load(), "the reader must see the rewritten content")
	assert.Equal(t, []byte("masked"), req.Body)
}

func TestStagePlan_GroupBatches_RewritersThenReaders(t *testing.T) {
	mask1 := &fakePlugin{name: "b_mask1", stages: preReq, result: &Result{}, mutReq: true}
	mask2 := &fakePlugin{name: "c_mask2", stages: preReq, result: &Result{}, mutReq: true}
	readA := readerPlugin{&fakePlugin{name: "a_read", stages: preReq, result: &Result{}}}
	readD := readerPlugin{&fakePlugin{name: "d_read", stages: preReq, result: &Result{}}}
	neutral := &fakePlugin{name: "e_rate", stages: preReq, result: &Result{}}
	respMask := &fakePlugin{name: "f_respmask", stages: preReq, result: &Result{}, mutResp: true}
	reg := newRegistry(t, mask1, mask2, readA, readD, neutral, respMask)

	tests := []struct {
		name  string
		specs []polSpec
		want  [][]string
	}{
		{
			name:  "rewriter then reader are two batches, readers stay parallel",
			specs: []polSpec{pre("a_read", 0, true), pre("b_mask1", 0, true), pre("d_read", 0, true)},
			want:  [][]string{{"b_mask1"}, {"a_read", "d_read"}},
		},
		{
			name:  "two rewriters keep their mutual sequencing, readers follow the last",
			specs: []polSpec{pre("a_read", 0, true), pre("b_mask1", 0, true), pre("c_mask2", 0, true)},
			want:  [][]string{{"b_mask1"}, {"c_mask2"}, {"a_read"}},
		},
		{
			name:  "two readers only stay in one parallel batch",
			specs: []polSpec{pre("a_read", 0, true), pre("d_read", 0, true)},
			want:  [][]string{{"a_read", "d_read"}},
		},
		{
			name:  "neutral plugin keeps its place with the rewriter",
			specs: []polSpec{pre("a_read", 0, true), pre("b_mask1", 0, true), pre("e_rate", 0, true)},
			want:  [][]string{{"b_mask1", "e_rate"}, {"a_read"}},
		},
		{
			name:  "a response-body rewriter does not gate a reader at a request stage",
			specs: []polSpec{pre("a_read", 0, true), pre("f_respmask", 0, true)},
			want:  [][]string{{"a_read", "f_respmask"}},
		},
		{
			name:  "different priorities are untouched",
			specs: []polSpec{pre("a_read", 0, true), pre("b_mask1", 1, true)},
			want:  [][]string{{"a_read"}, {"b_mask1"}},
		},
		{
			name:  "a non-parallel entry is a boundary the split never crosses",
			specs: []polSpec{pre("a_read", 0, true), pre("b_mask1", 0, false), pre("d_read", 0, true)},
			want:  [][]string{{"a_read"}, {"b_mask1"}, {"d_read"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := NewStagePlan(reg, policies(t, tt.specs...), nil)
			assert.Equal(t, tt.want, batchSlugs(plan.batchesFor(policy.StagePreRequest)))
		})
	}
}

func TestStagePlan_GroupBatches_ReaderAfterRewriterOnResponseStage(t *testing.T) {
	stages := []policy.Stage{policy.StagePreResponse}
	mask := &fakePlugin{name: "z_mask", stages: stages, result: &Result{}, mutResp: true}
	read := readerPlugin{&fakePlugin{name: "a_read", stages: stages, result: &Result{}}}
	reg := newRegistry(t, mask, read)

	pols := policies(t,
		polSpec{slug: "a_read", enabled: true, parallel: true, stages: stages},
		polSpec{slug: "z_mask", enabled: true, parallel: true, stages: stages},
	)
	plan := NewStagePlan(reg, pols, nil)
	assert.Equal(t, [][]string{{"z_mask"}, {"a_read"}}, batchSlugs(plan.batchesFor(policy.StagePreResponse)))
}

func TestExecutor_RunStage_ReadersStillRunConcurrently(t *testing.T) {
	var calls int32
	mk := func(name string) Plugin {
		return readerPlugin{&fakePlugin{
			name: name, stages: preReq, result: &Result{}, delay: 50 * time.Millisecond, calls: &calls,
		}}
	}
	exec := NewExecutor(newRegistry(t, mk("a"), mk("b"), mk("c")), nil)

	start := time.Now()
	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: policies(t, pre("a", 0, true), pre("b", 0, true), pre("c", 0, true)),
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls))
	assert.Less(t, time.Since(start), 120*time.Millisecond, "three readers must still overlap")
}
