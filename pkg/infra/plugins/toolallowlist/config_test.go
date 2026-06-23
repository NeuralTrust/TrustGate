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

package toolallowlist

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{
			name:     "valid allow only",
			settings: map[string]any{"allow_tools": []string{"search_*"}},
		},
		{
			name:     "valid deny only",
			settings: map[string]any{"deny_tools": []string{"delete_*"}},
		},
		{
			name: "valid allow and deny",
			settings: map[string]any{
				"allow_tools": []string{"search_*"},
				"deny_tools":  []string{"search_internal"},
			},
		},
		{
			name:     "valid inert scope consumer",
			settings: map[string]any{"allow_tools": []string{"search_*"}, "scope": "consumer"},
		},
		{
			name:     "valid inert scope global",
			settings: map[string]any{"allow_tools": []string{"search_*"}, "scope": "global"},
		},
		{
			name:     "valid explicit on_empty",
			settings: map[string]any{"allow_tools": []string{"search_*"}, "on_empty_after_filter": "strip_tools_field"},
		},
		{
			name:     "missing both lists",
			settings: map[string]any{},
			wantErr:  true,
		},
		{
			name:     "empty both lists",
			settings: map[string]any{"allow_tools": []string{}, "deny_tools": []string{}},
			wantErr:  true,
		},
		{
			name:     "blank pattern",
			settings: map[string]any{"allow_tools": []string{"search_*", "  "}},
			wantErr:  true,
		},
		{
			name:     "bad glob in allow",
			settings: map[string]any{"allow_tools": []string{"[a-"}},
			wantErr:  true,
		},
		{
			name:     "bad glob in deny",
			settings: map[string]any{"deny_tools": []string{"[a-"}},
			wantErr:  true,
		},
		{
			name:     "bad on_empty",
			settings: map[string]any{"allow_tools": []string{"search_*"}, "on_empty_after_filter": "drop"},
			wantErr:  true,
		},
		{
			name:     "bad scope",
			settings: map[string]any{"allow_tools": []string{"search_*"}, "scope": "team"},
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	cfg, err := parseConfig(map[string]any{"allow_tools": []string{"search_*"}})
	require.NoError(t, err)
	assert.Equal(t, onEmptyReject, cfg.OnEmptyAfterFilter)
}

func TestNewErrorBody(t *testing.T) {
	body := newErrorBody([]string{"delete_db", "calculate"})
	assert.Equal(t, "no_tools_allowed", body.Error.Type)
	assert.Equal(t, []string{"delete_db", "calculate"}, body.Error.Requested)
	assert.Equal(t, []string{}, body.Error.AllowedAfterFilter)

	raw, err := json.Marshal(body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"error":{"type":"no_tools_allowed","requested":["delete_db","calculate"],"allowed_after_filter":[]}}`, string(raw))
}

func TestToolAllowlistDataActions(t *testing.T) {
	data := ToolAllowlistData{
		Provider:       "openai",
		ToolsRequested: []string{"search_web", "delete_db"},
		ToolsAllowed:   []string{"search_web"},
		ToolsRemoved:   []string{"delete_db"},
		Action:         actionFiltered,
		OnEmpty:        onEmptyReject,
		Decision:       "enforced",
	}
	assert.Equal(t, actionFiltered, data.Action)
	assert.NotEqual(t, actionNoTools, data.Action)
	assert.NotEqual(t, actionRejected, data.Action)
	assert.NotEqual(t, actionStripped, data.Action)
	assert.NotEqual(t, actionPassThrough, data.Action)
	assert.NotEqual(t, actionSkipped, data.Action)
}
