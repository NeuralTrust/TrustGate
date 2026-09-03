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

package valuecopy_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/valuecopy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeep_SharesNoContainerWithTheOriginal(t *testing.T) {
	cases := []struct {
		name    string
		build   func() (original any, mutate func())
		wantOut any
	}{
		{
			name: "nested map",
			build: func() (any, func()) {
				inner := map[string]any{"category": "toxicity", "score": 0.91}
				original := map[string]any{"detail": inner}
				return original, func() {
					inner["category"] = "mutated"
					delete(inner, "score")
				}
			},
			wantOut: map[string]any{"detail": map[string]any{"category": "toxicity", "score": 0.91}},
		},
		{
			name: "map inside a slice",
			build: func() (any, func()) {
				entry := map[string]any{"entity": "email"}
				original := []any{entry}
				return original, func() { entry["entity"] = "mutated" }
			},
			wantOut: []any{map[string]any{"entity": "email"}},
		},
		{
			name: "concrete map type keeps its type",
			build: func() (any, func()) {
				original := map[string]float64{"pii": 0.5, "toxicity": 0.9}
				return original, func() { delete(original, "pii") }
			},
			wantOut: map[string]float64{"pii": 0.5, "toxicity": 0.9},
		},
		{
			name: "string slice",
			build: func() (any, func()) {
				original := []string{"pii", "toxicity"}
				return original, func() { original[0] = "mutated" }
			},
			wantOut: []string{"pii", "toxicity"},
		},
		{
			name: "array of maps",
			build: func() (any, func()) {
				inner := map[string]string{"k": "v"}
				original := [1]map[string]string{inner}
				return original, func() { inner["k"] = "mutated" }
			},
			wantOut: [1]map[string]string{{"k": "v"}},
		},
		{
			name: "map with a nil interface value",
			build: func() (any, func()) {
				original := map[string]any{"present": 1, "absent": nil}
				return original, func() { original["present"] = "mutated" }
			},
			wantOut: map[string]any{"present": 1, "absent": nil},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original, mutate := tc.build()
			got := valuecopy.Deep(original)
			mutate()
			assert.Equal(t, tc.wantOut, got)
		})
	}
}

func TestDeep_PassesThroughValuesWithNothingToCopy(t *testing.T) {
	cases := []struct {
		name string
		in   any
	}{
		{"nil", nil},
		{"string", "text"},
		{"float", 0.91},
		{"bool", true},
		{"nil map stays nil", map[string]any(nil)},
		{"nil slice stays nil", []any(nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.in, valuecopy.Deep(tc.in))
		})
	}
}

func TestDeep_TerminatesOnCyclicValues(t *testing.T) {
	cyclic := map[string]any{"name": "loop"}
	cyclic["self"] = cyclic

	got := valuecopy.Deep(cyclic)

	// The contract is that the copy stops at MaxDepth instead of following the
	// cycle forever; the shallow levels are still owned.
	out, ok := got.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "loop", out["name"])
	cyclic["name"] = "mutated"
	assert.Equal(t, "loop", out["name"])
}

// Run under -race this is the regression test for RUN-1261: over a shared map
// the detector reports the unsynchronised access between the producer's
// goroutine and the encoder's, which is the access that made json/v2 panic in
// production. Over an owned copy there is no shared memory left to race on, so
// it cannot fail.
func TestDeep_CopyMarshalsSafelyWhileTheProducerMutatesTheOriginal(t *testing.T) {
	const rounds = 300

	original := map[string]any{"category": "toxicity", "score": 0.91, "model": "guard-v2"}
	owned := valuecopy.Deep(original)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range rounds {
			key := fmt.Sprintf("extra-%d", i)
			original["category"] = key
			original[key] = i
			delete(original, key)
		}
	}()

	first, err := json.Marshal(owned)
	require.NoError(t, err)
	for range rounds {
		again, err := json.Marshal(owned)
		require.NoError(t, err)
		require.Equal(t, string(first), string(again), "an owned copy must marshal to the same bytes every time")
	}
	<-done
}
