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

func TestApplyRulesFrom(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		rules     []Rule
		input     string
		from      int
		want      string
		wantFired []int
	}{
		{
			name:  "from zero matches applyRules",
			rules: []Rule{{Pattern: `(\d{3})-(\d{4})`, Replacement: "$1-XXXX"}, {Pattern: "^foo$", Replacement: "bar", Multiline: true}},
			input: "call 555-1234\nfoo", want: "call 555-XXXX\nbar", wantFired: []int{0, 1},
		},
		{
			// RUN-1745 F2: the placeholder an earlier block released matches the
			// rule's own pattern.
			name:  "a placeholder already released is left alone",
			rules: []Rule{{Pattern: `(?i)ssn`, Replacement: "[SSN]"}},
			input: "my [SSN] is 1234", from: len("my [SSN] is 1"), want: "my [SSN] is 1234",
		},
		{
			name:  "a new match after released text is replaced",
			rules: []Rule{{Pattern: `(?i)ssn`, Replacement: "[SSN]"}},
			input: "my [SSN] and ssn", from: len("my [SSN] and "), want: "my [SSN] and [SSN]", wantFired: []int{0},
		},
		{
			// RUN-1745 F4: past the accumulation cap the window starts mid-text.
			name:  "an anchor at the start of a tail window is left alone",
			rules: []Rule{{Pattern: `^\d{3}`, Replacement: "NNN"}},
			input: "123 more text", from: len("123 more"), want: "123 more text",
		},
		{
			name:  "a match straddling into the new text is still replaced",
			rules: []Rule{{Pattern: `\d{16}`, Replacement: "[CARD]"}},
			input: "card 4111111111111111", from: len("card 411111"), want: "card [CARD]", wantFired: []int{0},
		},
		{
			// The first rule rewrote text before from, so the second judges it
			// again instead of trusting what earlier blocks saw there.
			name:  "a straddling replacement moves from back for later rules",
			rules: []Rule{{Pattern: "ab", Replacement: "YYb"}, {Pattern: "Y", Replacement: "Z"}},
			input: "xab", from: 2, want: "xZZb", wantFired: []int{0, 1},
		},
		{
			name:  "nothing past from matches",
			rules: []Rule{{Pattern: `\d{16}`, Replacement: "[CARD]"}},
			input: "4111111111111111 then words", from: 20, want: "4111111111111111 then words",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rules := mustCompile(t, tt.rules...)
			got, fired := applyRulesFrom(rules, tt.input, tt.from)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantFired, fired)
			if tt.from == 0 {
				want, _ := applyRules(rules, tt.input)
				assert.Equal(t, want, got, "from zero must rewrite exactly as the buffered path")
			}
		})
	}
}
