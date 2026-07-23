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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

func TestSetExtrasNilSafe(t *testing.T) {
	t.Parallel()
	assert.NotPanics(t, func() {
		setExtras(nil, ModerationData{Decision: "allowed"})
	})
	assert.NotPanics(t, func() {
		setExtras(metrics.NewEventContext(nil), ModerationData{Decision: "allowed"})
	})
}

func TestRecordScoreSetsMaxCategory(t *testing.T) {
	t.Parallel()
	assert.NotPanics(t, func() {
		recordScore(nil, ModerationData{MaxScoreCategory: "hate", MaxScore: 0.9})
	})

	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)
	recordScore(metrics.NewEventContext(span), ModerationData{MaxScoreCategory: "hate", MaxScore: 0.87})

	attrs := span.PluginAttrsCopy()
	require.Equal(t, "hate", attrs.ScoreLabel)
	require.NotNil(t, attrs.Score)
	assert.InDelta(t, 0.87, *attrs.Score, 1e-9)
}

func TestRecordScoreNoCategoryIsNoOp(t *testing.T) {
	t.Parallel()
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)
	recordScore(metrics.NewEventContext(span), ModerationData{MaxScore: 0.5})

	attrs := span.PluginAttrsCopy()
	assert.Empty(t, attrs.ScoreLabel)
	assert.Nil(t, attrs.Score)
}

func TestModerationDataOmitempty(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(ModerationData{})
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &fields))

	_, hasMaxScore := fields["max_score"]
	_, hasFlaggedByOpenAI := fields["flagged_by_openai"]
	assert.True(t, hasMaxScore, "max_score must always be present")
	assert.True(t, hasFlaggedByOpenAI, "flagged_by_openai must always be present")

	for _, key := range []string{"model", "category_scores", "max_score_category", "flagged_categories", "decision"} {
		_, present := fields[key]
		assert.Falsef(t, present, "%q must be omitted when empty", key)
	}
}

func TestViolationOmitempty(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(violation{Category: "hate", Score: 0.42})
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &fields))

	_, hasCategory := fields["category"]
	_, hasScore := fields["score"]
	_, hasThreshold := fields["threshold"]
	assert.True(t, hasCategory)
	assert.True(t, hasScore)
	assert.False(t, hasThreshold, "threshold must be omitted when zero")

	raw, err = json.Marshal(violation{Category: "hate", Score: 0.91, Threshold: 0.7})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &fields))
	_, hasThreshold = fields["threshold"]
	assert.True(t, hasThreshold, "threshold must be present when non-zero")
}
