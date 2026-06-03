package plugins

import (
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
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

	plan := NewStagePlan(reg, pols)

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
	plan := NewStagePlan(nil, nil)
	assert.False(t, plan.Has(policy.StagePreRequest))
	assert.Nil(t, plan.entriesFor(policy.StagePreRequest))
}

func TestStagePlan_NilReceiverIsSafe(t *testing.T) {
	var plan *StagePlan
	assert.False(t, plan.Has(policy.StagePreRequest))
	assert.Nil(t, plan.entriesFor(policy.StagePreRequest))
}
