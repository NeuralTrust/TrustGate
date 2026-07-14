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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		settings map[string]any
		wantLen  int
	}{
		{
			name: "single request rule",
			settings: map[string]any{
				"target": "request",
				"rules": []any{
					map[string]any{"pattern": "foo", "replacement": "bar"},
				},
			},
			wantLen: 1,
		},
		{
			name: "many response rules with flags",
			settings: map[string]any{
				"target": "response",
				"rules": []any{
					map[string]any{"pattern": "foo", "replacement": "bar", "case_insensitive": true},
					map[string]any{"pattern": "^baz$", "replacement": "qux", "multiline": true},
				},
			},
			wantLen: 2,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parseConfig(tt.settings)
			require.NoError(t, err)
			assert.Len(t, cfg.compiled, tt.wantLen)
		})
	}
}

func TestParseConfigErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  error
	}{
		{
			name: "missing target",
			settings: map[string]any{
				"rules": []any{map[string]any{"pattern": "foo", "replacement": "bar"}},
			},
			wantErr: ErrInvalidTarget,
		},
		{
			name: "unknown target",
			settings: map[string]any{
				"target": "both",
				"rules":  []any{map[string]any{"pattern": "foo", "replacement": "bar"}},
			},
			wantErr: ErrInvalidTarget,
		},
		{
			name:     "empty rules",
			settings: map[string]any{"target": "request", "rules": []any{}},
			wantErr:  ErrNoRules,
		},
		{
			name: "empty pattern",
			settings: map[string]any{
				"target": "request",
				"rules":  []any{map[string]any{"pattern": "  ", "replacement": "bar"}},
			},
			wantErr: ErrEmptyPattern,
		},
		{
			name: "invalid group",
			settings: map[string]any{
				"target": "request",
				"rules":  []any{map[string]any{"pattern": "(", "replacement": "x"}},
			},
			wantErr: ErrBadPattern,
		},
		{
			name: "backreference rejected",
			settings: map[string]any{
				"target": "request",
				"rules":  []any{map[string]any{"pattern": `\1`, "replacement": "x"}},
			},
			wantErr: ErrBadPattern,
		},
		{
			name: "lookahead rejected",
			settings: map[string]any{
				"target": "request",
				"rules":  []any{map[string]any{"pattern": "(?=x)", "replacement": "y"}},
			},
			wantErr: ErrBadPattern,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseConfig(tt.settings)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.wantErr))
		})
	}
}

func TestBuildPattern(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rule Rule
		want string
	}{
		{name: "plain", rule: Rule{Pattern: "foo"}, want: "foo"},
		{name: "case insensitive", rule: Rule{Pattern: "foo", CaseInsensitive: true}, want: "(?i)foo"},
		{name: "multiline", rule: Rule{Pattern: "^foo$", Multiline: true}, want: "(?m)^foo$"},
		{name: "both flags", rule: Rule{Pattern: "foo", CaseInsensitive: true, Multiline: true}, want: "(?i)(?m)foo"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, buildPattern(tt.rule))
		})
	}
}

func TestSettingsLegHelpers(t *testing.T) {
	t.Parallel()
	req := Settings{Target: targetRequest}
	assert.True(t, req.isRequestLeg())
	assert.False(t, req.isResponseLeg())

	resp := Settings{Target: targetResponse}
	assert.True(t, resp.isResponseLeg())
	assert.False(t, resp.isRequestLeg())
}
