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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
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

func scoped(p *policy.Policy, scope *policy.MCPScope) *policy.Policy {
	p.MCPScope = scope
	return p
}

func preRequestPlugins(t *testing.T, names ...string) Registry {
	t.Helper()
	ps := make([]Plugin, 0, len(names))
	for _, name := range names {
		ps = append(ps, &fakePlugin{name: name, stages: []policy.Stage{policy.StagePreRequest}, result: &Result{}})
	}
	return newRegistry(t, ps...)
}

func entrySlugs(entries []chainEntry) []string {
	out := make([]string, len(entries))
	for i, entry := range entries {
		out[i] = entry.config.Slug
	}
	return out
}

func TestStagePlan_EqualPriorityOrdersBySpecificityDesc(t *testing.T) {
	registryID := ids.New[ids.RegistryKind]()
	reg := preRequestPlugins(t, "a_consumer", "b_registry", "c_tool", "d_tool_principal")
	pre := []policy.Stage{policy.StagePreRequest}

	pols := policies(t,
		polSpec{slug: "a_consumer", enabled: true, priority: 10, stages: pre},
		polSpec{slug: "b_registry", enabled: true, priority: 10, stages: pre},
		polSpec{slug: "c_tool", enabled: true, priority: 10, stages: pre},
		polSpec{slug: "d_tool_principal", enabled: true, priority: 10, stages: pre},
	)
	scoped(pols[1], &policy.MCPScope{RegistryIDs: []ids.RegistryID{registryID}})
	scoped(pols[2], &policy.MCPScope{Tools: []policy.MCPToolRef{{RegistryID: registryID, Tool: "run_query"}}})
	scoped(pols[3], &policy.MCPScope{
		Tools:  []policy.MCPToolRef{{RegistryID: registryID, Tool: "run_query"}},
		Groups: []string{"Finanzas"},
	})

	plan := NewStagePlan(reg, pols, nil)

	want := []string{"d_tool_principal", "c_tool", "b_registry", "a_consumer"}
	assert.Equal(t, want, entrySlugs(plan.entriesFor(policy.StagePreRequest)),
		"at equal priority the most specific scope must run first, ahead of slug order")
	assert.Equal(t, [][]string{{"d_tool_principal"}, {"c_tool"}, {"b_registry"}, {"a_consumer"}},
		batchSlugs(plan.batchesFor(policy.StagePreRequest)))
	assert.Equal(t, want, entrySlugs(buildStageChain(reg, pols, policy.StagePreRequest)),
		"the executor's ad-hoc chain must apply the same order as the precompiled plan")
}

func TestStagePlan_PriorityStillBeatsSpecificity(t *testing.T) {
	registryID := ids.New[ids.RegistryKind]()
	reg := preRequestPlugins(t, "consumer_wide", "tool_scoped")
	pre := []policy.Stage{policy.StagePreRequest}

	pols := policies(t,
		polSpec{slug: "tool_scoped", enabled: true, priority: 20, stages: pre},
		polSpec{slug: "consumer_wide", enabled: true, priority: 10, stages: pre},
	)
	scoped(pols[0], &policy.MCPScope{Tools: []policy.MCPToolRef{{RegistryID: registryID, Tool: "run_query"}}})

	plan := NewStagePlan(reg, pols, nil)
	assert.Equal(t, []string{"consumer_wide", "tool_scoped"}, entrySlugs(plan.entriesFor(policy.StagePreRequest)))
}

func TestStagePlan_ParallelBatchGroupsByPriorityOnly(t *testing.T) {
	registryID := ids.New[ids.RegistryKind]()
	reg := preRequestPlugins(t, "a_consumer", "b_tool", "c_later")
	pre := []policy.Stage{policy.StagePreRequest}

	pols := policies(t,
		polSpec{slug: "a_consumer", enabled: true, priority: 10, parallel: true, stages: pre},
		polSpec{slug: "b_tool", enabled: true, priority: 10, parallel: true, stages: pre},
		polSpec{slug: "c_later", enabled: true, priority: 20, parallel: true, stages: pre},
	)
	scoped(pols[1], &policy.MCPScope{Tools: []policy.MCPToolRef{{RegistryID: registryID, Tool: "run_query"}}})

	plan := NewStagePlan(reg, pols, nil)
	assert.Equal(t, [][]string{{"b_tool", "a_consumer"}, {"c_later"}}, batchSlugs(plan.batchesFor(policy.StagePreRequest)),
		"specificity orders inside a parallel batch but never splits it")
}

func TestStagePlan_EqualSpecificityFallsBackToSlugThenID(t *testing.T) {
	registryID := ids.New[ids.RegistryKind]()
	reg := preRequestPlugins(t, "x", "y")
	pre := []policy.Stage{policy.StagePreRequest}
	scope := func() *policy.MCPScope {
		return &policy.MCPScope{RegistryIDs: []ids.RegistryID{registryID}}
	}

	pols := policies(t,
		polSpec{slug: "y", enabled: true, priority: 10, stages: pre},
		polSpec{slug: "x", enabled: true, priority: 10, stages: pre},
		polSpec{slug: "x", enabled: true, priority: 10, stages: pre},
	)
	for _, p := range pols {
		scoped(p, scope())
	}
	firstX, secondX := pols[1], pols[2]
	if secondX.ID.String() < firstX.ID.String() {
		firstX, secondX = secondX, firstX
	}

	plan := NewStagePlan(reg, pols, nil)
	entries := plan.entriesFor(policy.StagePreRequest)
	require.Len(t, entries, 3)
	assert.Equal(t, []string{"x", "x", "y"}, entrySlugs(entries))
	assert.Equal(t, firstX.ID.String(), entries[0].config.ID)
	assert.Equal(t, secondX.ID.String(), entries[1].config.ID)
}

func TestStagePlan_UnionRegroupsAcrossPlans(t *testing.T) {
	registryID := ids.New[ids.RegistryKind]()
	reg := preRequestPlugins(t, "a_scoped", "b_base", "c_first")
	pre := []policy.Stage{policy.StagePreRequest}

	base := NewStagePlan(reg, policies(t,
		polSpec{slug: "b_base", enabled: true, priority: 10, parallel: true, stages: pre},
	), nil)
	scopedPols := policies(t,
		polSpec{slug: "a_scoped", enabled: true, priority: 10, parallel: true, stages: pre},
	)
	scoped(scopedPols[0], &policy.MCPScope{Tools: []policy.MCPToolRef{{RegistryID: registryID, Tool: "run_query"}}})
	scopedPlan := NewStagePlan(reg, scopedPols, nil)
	first := NewStagePlan(reg, policies(t,
		polSpec{slug: "c_first", enabled: true, priority: 5, stages: pre},
	), nil)

	union := base.Union(scopedPlan, first)

	assert.Equal(t, []string{"c_first", "a_scoped", "b_base"}, entrySlugs(union.entriesFor(policy.StagePreRequest)))
	assert.Equal(t, [][]string{{"c_first"}, {"a_scoped", "b_base"}}, batchSlugs(union.batchesFor(policy.StagePreRequest)),
		"entries from different plans must share a parallel batch when priority matches")
	assert.False(t, union.Has(policy.StagePostResponse))

	assert.Equal(t, []string{"b_base"}, entrySlugs(base.entriesFor(policy.StagePreRequest)), "Union must not mutate its receiver")
	assert.Equal(t, []string{"a_scoped"}, entrySlugs(scopedPlan.entriesFor(policy.StagePreRequest)), "Union must not mutate its inputs")
}

func TestStagePlan_UnionDedupsAndHandlesNil(t *testing.T) {
	reg := preRequestPlugins(t, "only")
	pre := []policy.Stage{policy.StagePreRequest}
	plan := NewStagePlan(reg, policies(t,
		polSpec{slug: "only", enabled: true, priority: 1, stages: pre},
	), nil)

	assert.Same(t, plan, plan.Union(), "without extras Union returns the receiver")
	assert.Equal(t, []string{"only"}, entrySlugs(plan.Union(plan).entriesFor(policy.StagePreRequest)),
		"the same policy present in several plans enters once")

	var nilPlan *StagePlan
	fromNil := nilPlan.Union(plan)
	assert.Equal(t, []string{"only"}, entrySlugs(fromNil.entriesFor(policy.StagePreRequest)))
	assert.Equal(t, [][]string{{"only"}}, batchSlugs(fromNil.batchesFor(policy.StagePreRequest)))

	empty := plan.Union(nilPlan, NewStagePlan(nil, nil, nil))
	assert.Equal(t, []string{"only"}, entrySlugs(empty.entriesFor(policy.StagePreRequest)))
}
