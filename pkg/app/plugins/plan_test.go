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
	"bytes"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStagePlan_GroupsByStageAndSortsByPriority(t *testing.T) {
	pre := &fakePlugin{name: "pre", stages: []policy.Stage{policy.StagePreRequest}, result: &Result{}}
	both := &fakePlugin{
		name:   "both",
		stages: []policy.Stage{policy.StagePreRequest, policy.StagePostResponse},
		result: &Result{},
	}
	reg := newRegistry(t, pre, both)

	pols := policies(t,
		polSpec{slug: "both", enabled: true, priority: 2, stages: []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}},
		polSpec{slug: "pre", enabled: true, priority: 1, stages: []policy.Stage{policy.StagePreRequest}},
		polSpec{slug: "disabled", enabled: false},
	)

	plan := NewStagePlan(reg, pols, nil)

	require.True(t, plan.Has(policy.StagePreRequest))
	require.True(t, plan.Has(policy.StagePostResponse))
	require.False(t, plan.Has(policy.StagePostRequest))

	preEntries := plan.entriesFor(policy.StagePreRequest)
	require.Len(t, preEntries, 2)
	assert.Equal(t, "pre", preEntries[0].plugin.Name(), "lower priority must come first")
	assert.Equal(t, "both", preEntries[1].plugin.Name())

	postEntries := plan.entriesFor(policy.StagePostResponse)
	require.Len(t, postEntries, 1)
	assert.Equal(t, "both", postEntries[0].plugin.Name())
}

func TestStagePlan_NilRegistryYieldsEmptyPlan(t *testing.T) {
	plan := NewStagePlan(nil, nil, nil)
	assert.False(t, plan.Has(policy.StagePreRequest))
	assert.Nil(t, plan.entriesFor(policy.StagePreRequest))
	assert.Nil(t, plan.batchesFor(policy.StagePreRequest))
}

func TestStagePlan_NilReceiverIsSafe(t *testing.T) {
	var plan *StagePlan
	assert.False(t, plan.Has(policy.StagePreRequest))
	assert.Nil(t, plan.entriesFor(policy.StagePreRequest))
	assert.Nil(t, plan.batchesFor(policy.StagePreRequest))
}

func batchSlugs(batches [][]chainEntry) [][]string {
	out := make([][]string, len(batches))
	for i, batch := range batches {
		slugs := make([]string, len(batch))
		for j, entry := range batch {
			slugs[j] = entry.config.Slug
		}
		out[i] = slugs
	}
	return out
}

func TestStagePlan_GroupBatchesCapsOneMutatorPerBatch(t *testing.T) {
	reqA := &fakePlugin{name: "a_req", stages: []policy.Stage{policy.StagePreRequest}, result: &Result{}, mutReq: true}
	reqB := &fakePlugin{name: "b_req", stages: []policy.Stage{policy.StagePreRequest}, result: &Result{}, mutReq: true}
	plain := &fakePlugin{name: "c_plain", stages: []policy.Stage{policy.StagePreRequest}, result: &Result{}}
	reg := newRegistry(t, reqA, reqB, plain)

	pols := policies(t,
		polSpec{slug: "a_req", enabled: true, priority: 1, parallel: true, stages: []policy.Stage{policy.StagePreRequest}},
		polSpec{slug: "b_req", enabled: true, priority: 1, parallel: true, stages: []policy.Stage{policy.StagePreRequest}},
		polSpec{slug: "c_plain", enabled: true, priority: 1, parallel: true, stages: []policy.Stage{policy.StagePreRequest}},
	)
	plan := NewStagePlan(reg, pols, nil)

	batches := plan.batchesFor(policy.StagePreRequest)
	assert.Equal(t, [][]string{{"a_req"}, {"b_req", "c_plain"}}, batchSlugs(batches))
	for _, batch := range batches {
		reqMutators := 0
		for _, entry := range batch {
			if entry.mutatesReq {
				reqMutators++
			}
		}
		assert.LessOrEqual(t, reqMutators, 1, "a parallel batch must admit at most one request-body mutator")
	}
}

func TestStagePlan_GroupBatchesForcesSequentialAndLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	reqA := &fakePlugin{name: "a_req", stages: []policy.Stage{policy.StagePreRequest}, result: &Result{}, mutReq: true}
	reqB := &fakePlugin{name: "b_req", stages: []policy.Stage{policy.StagePreRequest}, result: &Result{}, mutReq: true}
	reg := newRegistry(t, reqA, reqB)

	pols := policies(t,
		polSpec{slug: "a_req", enabled: true, priority: 1, parallel: true, stages: []policy.Stage{policy.StagePreRequest}},
		polSpec{slug: "b_req", enabled: true, priority: 1, parallel: true, stages: []policy.Stage{policy.StagePreRequest}},
	)
	plan := NewStagePlan(reg, pols, logger)

	batches := plan.batchesFor(policy.StagePreRequest)
	require.Len(t, batches, 2)
	out := buf.String()
	assert.Contains(t, out, "forced sequential")
	assert.Contains(t, out, "capability=request_body")
	assert.Contains(t, out, "slug=b_req")
}

func TestStagePlan_GroupBatchesIsDeterministicByPriorityThenSlug(t *testing.T) {
	mk := func(name string) *fakePlugin {
		return &fakePlugin{name: name, stages: []policy.Stage{policy.StagePreRequest}, result: &Result{}}
	}
	reg := newRegistry(t, mk("c"), mk("a"), mk("b"))

	pols := policies(t,
		polSpec{slug: "c", enabled: true, priority: 1, parallel: true, stages: []policy.Stage{policy.StagePreRequest}},
		polSpec{slug: "a", enabled: true, priority: 1, parallel: true, stages: []policy.Stage{policy.StagePreRequest}},
		polSpec{slug: "b", enabled: true, priority: 1, parallel: true, stages: []policy.Stage{policy.StagePreRequest}},
	)
	plan := NewStagePlan(reg, pols, nil)

	batches := plan.batchesFor(policy.StagePreRequest)
	assert.Equal(t, [][]string{{"a", "b", "c"}}, batchSlugs(batches))
}

func TestStagePlan_GroupBatchesNonParallelIsSingleton(t *testing.T) {
	mk := func(name string) *fakePlugin {
		return &fakePlugin{name: name, stages: []policy.Stage{policy.StagePreRequest}, result: &Result{}}
	}
	reg := newRegistry(t, mk("a"), mk("b"))

	pols := policies(t,
		polSpec{slug: "a", enabled: true, priority: 1, parallel: false, stages: []policy.Stage{policy.StagePreRequest}},
		polSpec{slug: "b", enabled: true, priority: 1, parallel: true, stages: []policy.Stage{policy.StagePreRequest}},
	)
	plan := NewStagePlan(reg, pols, nil)

	batches := plan.batchesFor(policy.StagePreRequest)
	assert.Equal(t, [][]string{{"a"}, {"b"}}, batchSlugs(batches))
}
