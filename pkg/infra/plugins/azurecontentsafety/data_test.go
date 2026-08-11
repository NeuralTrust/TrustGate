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

package azurecontentsafety

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

func TestRecordScoreTopBreach(t *testing.T) {
	t.Parallel()
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)

	recordScore(metrics.NewEventContext(span), []breachedCategory{
		{Category: "Hate", Severity: 4, Threshold: 2},
		{Category: "Violence", Severity: 6, Threshold: 2},
	})

	attrs := span.PluginAttrsCopy()
	require.Equal(t, "Violence", attrs.ScoreLabel)
	require.NotNil(t, attrs.Score)
	assert.InDelta(t, 6.0/azureSeverityScale, *attrs.Score, 1e-9)
}

func TestRecordScoreEmptyIsNoOp(t *testing.T) {
	t.Parallel()
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)

	recordScore(metrics.NewEventContext(span), nil)

	attrs := span.PluginAttrsCopy()
	assert.Empty(t, attrs.ScoreLabel)
	assert.Nil(t, attrs.Score)
}

func TestRecordScoreNilEventSafe(t *testing.T) {
	t.Parallel()
	assert.NotPanics(t, func() {
		recordScore(nil, []breachedCategory{{Category: "Hate", Severity: 4}})
	})
}
