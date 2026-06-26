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

package openaimoderation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAggregateMaxAcrossResults(t *testing.T) {
	t.Parallel()
	results := []moderationResult{
		{
			Flagged:        false,
			Categories:     map[string]bool{"hate": false, "violence": true},
			CategoryScores: map[string]float64{"hate": 0.40, "violence": 0.10},
		},
		{
			Flagged:        true,
			Categories:     map[string]bool{"hate": true, "violence": false},
			CategoryScores: map[string]float64{"hate": 0.82, "violence": 0.05},
		},
	}

	agg := aggregate(results)
	assert.InDelta(t, 0.82, agg.scores["hate"], 1e-9)
	assert.InDelta(t, 0.10, agg.scores["violence"], 1e-9)
	assert.True(t, agg.flagged["hate"], "hate flagged in second result")
	assert.True(t, agg.flagged["violence"], "violence flagged in first result")
	assert.True(t, agg.anyFlagged, "anyFlagged is OR of result.Flagged")
}

func TestAggregateEmpty(t *testing.T) {
	t.Parallel()
	agg := aggregate(nil)
	assert.Empty(t, agg.scores)
	assert.Empty(t, agg.flagged)
	assert.False(t, agg.anyFlagged)
}

func TestEvaluate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  Settings
		agg  aggregated
		want []violation
	}{
		{
			name: "threshold crossed",
			cfg:  Settings{Thresholds: map[string]float64{"hate": 0.7}},
			agg:  aggregated{scores: map[string]float64{"hate": 0.91}},
			want: []violation{{Category: "hate", Score: 0.91, Threshold: 0.7}},
		},
		{
			name: "threshold exactly met",
			cfg:  Settings{Thresholds: map[string]float64{"hate": 0.7}},
			agg:  aggregated{scores: map[string]float64{"hate": 0.7}},
			want: []violation{{Category: "hate", Score: 0.7, Threshold: 0.7}},
		},
		{
			name: "below threshold",
			cfg:  Settings{Thresholds: map[string]float64{"hate": 0.7}},
			agg:  aggregated{scores: map[string]float64{"hate": 0.5}},
			want: []violation{},
		},
		{
			name: "allow-list restricts evaluation",
			cfg:  Settings{Categories: []string{"hate"}, Thresholds: map[string]float64{"hate": 0.7, "violence": 0.5}},
			agg:  aggregated{scores: map[string]float64{"hate": 0.4, "violence": 0.99}},
			want: []violation{},
		},
		{
			name: "empty allow-list evaluates all present",
			cfg:  Settings{Thresholds: map[string]float64{"violence": 0.8}},
			agg:  aggregated{scores: map[string]float64{"violence": 0.85, "hate": 0.1}},
			want: []violation{{Category: "violence", Score: 0.85, Threshold: 0.8}},
		},
		{
			name: "block_on_flagged true adds flagged without threshold",
			cfg:  Settings{BlockOnFlagged: true},
			agg:  aggregated{scores: map[string]float64{"sexual": 0.3}, flagged: map[string]bool{"sexual": true}},
			want: []violation{{Category: "sexual", Score: 0.3}},
		},
		{
			name: "block_on_flagged false ignores flagged without threshold",
			cfg:  Settings{BlockOnFlagged: false},
			agg:  aggregated{scores: map[string]float64{"sexual": 0.3}, flagged: map[string]bool{"sexual": true}},
			want: []violation{},
		},
		{
			name: "no double-add when threshold and flagged",
			cfg:  Settings{BlockOnFlagged: true, Thresholds: map[string]float64{"hate": 0.7}},
			agg:  aggregated{scores: map[string]float64{"hate": 0.9}, flagged: map[string]bool{"hate": true}},
			want: []violation{{Category: "hate", Score: 0.9, Threshold: 0.7}},
		},
		{
			name: "duplicate allow-list entries reported once",
			cfg:  Settings{Categories: []string{"hate", "hate"}, Thresholds: map[string]float64{"hate": 0.7}},
			agg:  aggregated{scores: map[string]float64{"hate": 0.91}},
			want: []violation{{Category: "hate", Score: 0.91, Threshold: 0.7}},
		},
		{
			name: "deterministic sorted order",
			cfg:  Settings{BlockOnFlagged: true, Thresholds: map[string]float64{"violence": 0.5, "hate": 0.5, "sexual": 0.5}},
			agg:  aggregated{scores: map[string]float64{"violence": 0.6, "hate": 0.6, "sexual": 0.6}},
			want: []violation{
				{Category: "hate", Score: 0.6, Threshold: 0.5},
				{Category: "sexual", Score: 0.6, Threshold: 0.5},
				{Category: "violence", Score: 0.6, Threshold: 0.5},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := evaluate(tt.cfg, tt.agg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMaxScore(t *testing.T) {
	t.Parallel()
	cat, score := maxScore(aggregated{scores: map[string]float64{"hate": 0.2, "violence": 0.9, "sexual": 0.5}})
	assert.Equal(t, "violence", cat)
	assert.InDelta(t, 0.9, score, 1e-9)

	cat, score = maxScore(aggregated{scores: map[string]float64{}})
	assert.Equal(t, "", cat)
	assert.Zero(t, score)
}

func TestEvaluateBlockOnFlaggedRespectsAllowList(t *testing.T) {
	t.Parallel()
	cfg := Settings{Categories: []string{"hate"}, BlockOnFlagged: true}
	agg := aggregated{
		scores:  map[string]float64{"hate": 0.1, "sexual": 0.9},
		flagged: map[string]bool{"sexual": true},
	}
	got := evaluate(cfg, agg)
	require.Empty(t, got, "sexual is flagged but outside the allow-list")
}
