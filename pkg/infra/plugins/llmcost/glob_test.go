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

package llmcost

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{name: "exact", pattern: "gpt-5", input: "gpt-5", want: true},
		{name: "exact mismatch", pattern: "gpt-5", input: "gpt-4", want: false},
		{name: "trailing star", pattern: "claude-opus-*", input: "claude-opus-4", want: true},
		{name: "trailing star empty tail", pattern: "claude-opus-*", input: "claude-opus-", want: true},
		{name: "leading star", pattern: "*-mini", input: "gpt-5-mini", want: true},
		{name: "middle star", pattern: "gpt-*-mini", input: "gpt-5-mini", want: true},
		{name: "middle star no match", pattern: "gpt-*-mini", input: "gpt-5-nano", want: false},
		{name: "only star", pattern: "*", input: "anything", want: true},
		{name: "multiple stars", pattern: "a*b*c", input: "axxbyyc", want: true},
		{name: "multiple stars no match", pattern: "a*b*c", input: "axxbyy", want: false},
		{name: "no star no match", pattern: "gpt", input: "gpt-5", want: false},
		{name: "star matches empty", pattern: "gpt-5*", input: "gpt-5", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, GlobMatch(tt.pattern, tt.input))
		})
	}
}

func TestBestMatchExactWins(t *testing.T) {
	m := map[string]int{
		"claude-opus-*": 1,
		"claude-opus-4": 2,
	}
	got, ok := BestMatch(m, "claude-opus-4")
	require.True(t, ok)
	assert.Equal(t, 2, got)
}

func TestBestMatchMostSpecificGlobWins(t *testing.T) {
	m := map[string]int{
		"claude-*":      1,
		"claude-opus-*": 2,
	}
	got, ok := BestMatch(m, "claude-opus-4")
	require.True(t, ok)
	assert.Equal(t, 2, got)
}

func TestBestMatchNoMatch(t *testing.T) {
	m := map[string]int{
		"gpt-*": 1,
	}
	_, ok := BestMatch(m, "claude-opus-4")
	assert.False(t, ok)
}

func TestBestMatchSingleGlob(t *testing.T) {
	m := map[string]int{
		"gpt-5-*": 7,
	}
	got, ok := BestMatch(m, "gpt-5-mini")
	require.True(t, ok)
	assert.Equal(t, 7, got)
}

func TestBestMatchEmptyMap(t *testing.T) {
	_, ok := BestMatch(map[string]int{}, "gpt-5")
	assert.False(t, ok)
}
