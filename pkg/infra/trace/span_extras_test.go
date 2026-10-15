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

package trace_test

import (
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/require"
)

// siblingDeleter deletes a sibling key from its parent map when the encoder
// marshals it, reproducing the Go 1.27 encoding/json/v2 panic on demand: v2's
// sorted-map path collects a map's keys, sorts them, then looks each value up
// again with reflect MapIndex. A key gone by that second pass yields the zero
// Value and reflect.Value.Set panics on it (RUN-1261).
//
// The trigger sorts before its victim, so the deletion always lands between the
// two passes.
type siblingDeleter struct {
	parent map[string]any
	victim string
}

func (d siblingDeleter) MarshalJSON() ([]byte, error) {
	delete(d.parent, d.victim)
	return []byte(`"trigger"`), nil
}

func selfDeletingMap() map[string]any {
	m := map[string]any{}
	m["a_trigger"] = siblingDeleter{parent: m, victim: "z_victim"}
	m["m_filler"] = 1
	m["z_victim"] = "gone before the encoder looks it up"
	return m
}

func TestSetExtrasTakesOwnershipOfThePluginsMap(t *testing.T) {
	src := map[string]any{"nested": map[string]any{"category": "toxicity"}}

	rt := trace.New("trace-extras-owned", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, "trustguard")
	span.SetExtras(src)

	// Mutating the plugin's own map must not reach the span.
	src["nested"].(map[string]any)["category"] = "mutated"
	src["added"] = true

	stored, ok := span.PluginAttrsCopy().Extras.(map[string]any)
	require.True(t, ok, "extras should still be a map")
	require.NotContains(t, stored, "added", "the span kept a live handle on the plugin's map")
	nested, ok := stored["nested"].(map[string]any)
	require.True(t, ok, "nested value should still be a map")
	require.Equal(t, "toxicity", nested["category"],
		"the span shared a nested map with the plugin")
}

func TestSetExtrasMarshalSurvivesMetadataThatMutatesWhileEncoding(t *testing.T) {
	// The hazard is real, or this test proves nothing. If this stops panicking,
	// revisit the copy in SetExtras rather than deleting this test.
	require.Panics(t, func() { _, _ = json.Marshal(selfDeletingMap()) })

	rt := trace.New("trace-extras-hazard", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, "trustguard")
	span.SetExtras(selfDeletingMap())

	extras := span.PluginAttrsCopy().Extras
	require.NotPanics(t, func() {
		first, err := json.Marshal(extras)
		require.NoError(t, err)
		again, err := json.Marshal(extras)
		require.NoError(t, err)
		require.Equal(t, string(first), string(again),
			"extras must marshal to the same bytes every time")
	})
}
