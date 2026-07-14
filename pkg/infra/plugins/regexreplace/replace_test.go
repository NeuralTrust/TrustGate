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

package regexreplace

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustCompile(t *testing.T, rules ...Rule) []compiledRule {
	t.Helper()
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		re, err := regexp.Compile(buildPattern(r))
		require.NoError(t, err)
		out = append(out, compiledRule{re: re, replacement: r.Replacement})
	}
	return out
}

func TestApplyRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		rules       []Rule
		input       string
		want        string
		wantChanged bool
	}{
		{
			name:        "single match",
			rules:       []Rule{{Pattern: "foo", Replacement: "bar"}},
			input:       "foo baz",
			want:        "bar baz",
			wantChanged: true,
		},
		{
			name:        "capture group",
			rules:       []Rule{{Pattern: `(\w+)@example\.com`, Replacement: "$1@masked"}},
			input:       "alice@example.com",
			want:        "alice@masked",
			wantChanged: true,
		},
		{
			name:        "named group",
			rules:       []Rule{{Pattern: `(?P<name>\w+)@example\.com`, Replacement: "${name}@masked"}},
			input:       "bob@example.com",
			want:        "bob@masked",
			wantChanged: true,
		},
		{
			name: "chaining",
			rules: []Rule{
				{Pattern: "a", Replacement: "b"},
				{Pattern: "b", Replacement: "c"},
			},
			input:       "a",
			want:        "c",
			wantChanged: true,
		},
		{
			name:        "no match",
			rules:       []Rule{{Pattern: "zzz", Replacement: "x"}},
			input:       "foo bar",
			want:        "foo bar",
			wantChanged: false,
		},
		{
			name:        "empty replacement deletes",
			rules:       []Rule{{Pattern: `\d+`, Replacement: ""}},
			input:       "abc123def",
			want:        "abcdef",
			wantChanged: true,
		},
		{
			name:        "case insensitive flag matches",
			rules:       []Rule{{Pattern: "foo", Replacement: "bar", CaseInsensitive: true}},
			input:       "FOO baz",
			want:        "bar baz",
			wantChanged: true,
		},
		{
			name:        "case insensitive off does not match",
			rules:       []Rule{{Pattern: "foo", Replacement: "bar"}},
			input:       "FOO baz",
			want:        "FOO baz",
			wantChanged: false,
		},
		{
			name:        "multiline flag anchors each line",
			rules:       []Rule{{Pattern: "^foo$", Replacement: "bar", Multiline: true}},
			input:       "x\nfoo\ny",
			want:        "x\nbar\ny",
			wantChanged: true,
		},
		{
			name:        "multiline off does not anchor inner line",
			rules:       []Rule{{Pattern: "^foo$", Replacement: "bar"}},
			input:       "x\nfoo\ny",
			want:        "x\nfoo\ny",
			wantChanged: false,
		},
		{
			name: "net no-op",
			rules: []Rule{
				{Pattern: "a", Replacement: "b"},
				{Pattern: "b", Replacement: "a"},
			},
			input:       "a",
			want:        "a",
			wantChanged: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, changed := applyRules(mustCompile(t, tt.rules...), tt.input)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantChanged, changed)
		})
	}
}
