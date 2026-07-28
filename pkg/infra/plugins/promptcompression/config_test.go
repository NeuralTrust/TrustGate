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

package promptcompression

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
	}{
		{
			name:     "json only",
			settings: map[string]any{"compress_json": true},
		},
		{
			name: "all transforms with options",
			settings: map[string]any{
				"compress_json":               true,
				"normalize_whitespace":        true,
				"strip_ansi":                  true,
				"max_consecutive_blank_lines": 2,
				"min_length":                  64,
				"target_roles":                []any{"tool", "user"},
			},
		},
		{
			name:     "whitespace only",
			settings: map[string]any{"normalize_whitespace": true},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parseConfig(tt.settings)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, cfg.MaxConsecutiveBlankLines, 1)
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
			name:     "no transforms enabled",
			settings: map[string]any{},
			wantErr:  ErrNoTransforms,
		},
		{
			name:     "all transforms disabled",
			settings: map[string]any{"compress_json": false, "normalize_whitespace": false, "strip_ansi": false},
			wantErr:  ErrNoTransforms,
		},
		{
			name:     "negative min length",
			settings: map[string]any{"compress_json": true, "min_length": -1},
			wantErr:  ErrNegativeMin,
		},
		{
			name:     "blank line cap below one",
			settings: map[string]any{"compress_json": true, "max_consecutive_blank_lines": -2},
			wantErr:  ErrBadBlankLines,
		},
		{
			name:     "empty role",
			settings: map[string]any{"compress_json": true, "target_roles": []any{"  "}},
			wantErr:  ErrUnknownRole,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseConfig(tt.settings)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.wantErr), "expected %v, got %v", tt.wantErr, err)
		})
	}
}

func TestAppliesToRole(t *testing.T) {
	t.Parallel()
	all, err := parseConfig(map[string]any{"compress_json": true})
	require.NoError(t, err)
	assert.True(t, all.appliesToRole("system"))
	assert.True(t, all.appliesToRole("tool"))

	scoped, err := parseConfig(map[string]any{"compress_json": true, "target_roles": []any{"Tool"}})
	require.NoError(t, err)
	assert.True(t, scoped.appliesToRole("tool"))
	assert.True(t, scoped.appliesToRole("TOOL"))
	assert.False(t, scoped.appliesToRole("system"))
	assert.False(t, scoped.appliesToRole("user"))
}
