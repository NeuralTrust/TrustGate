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

package tooltransform

import (
	"reflect"
	"testing"
)

func TestMergePatch(t *testing.T) {
	tests := []struct {
		name   string
		target map[string]interface{}
		patch  map[string]interface{}
		want   map[string]interface{}
	}{
		{
			name:   "set scalar",
			target: map[string]interface{}{"type": "object"},
			patch:  map[string]interface{}{"title": "x"},
			want:   map[string]interface{}{"type": "object", "title": "x"},
		},
		{
			name:   "replace scalar",
			target: map[string]interface{}{"n": 1},
			patch:  map[string]interface{}{"n": 2},
			want:   map[string]interface{}{"n": 2},
		},
		{
			name:   "null deletes key",
			target: map[string]interface{}{"a": 1, "b": 2},
			patch:  map[string]interface{}{"b": nil},
			want:   map[string]interface{}{"a": 1},
		},
		{
			name:   "nested recurse",
			target: map[string]interface{}{"props": map[string]interface{}{"x": map[string]interface{}{"t": "s"}}},
			patch:  map[string]interface{}{"props": map[string]interface{}{"x": map[string]interface{}{"t": "n"}, "y": map[string]interface{}{"t": "s"}}},
			want:   map[string]interface{}{"props": map[string]interface{}{"x": map[string]interface{}{"t": "n"}, "y": map[string]interface{}{"t": "s"}}},
		},
		{
			name:   "nested null delete",
			target: map[string]interface{}{"props": map[string]interface{}{"x": 1, "y": 2}},
			patch:  map[string]interface{}{"props": map[string]interface{}{"y": nil}},
			want:   map[string]interface{}{"props": map[string]interface{}{"x": 1}},
		},
		{
			name:   "array replaces wholesale",
			target: map[string]interface{}{"required": []interface{}{"a", "b"}},
			patch:  map[string]interface{}{"required": []interface{}{"c"}},
			want:   map[string]interface{}{"required": []interface{}{"c"}},
		},
		{
			name:   "object replaces scalar no recurse",
			target: map[string]interface{}{"a": 5},
			patch:  map[string]interface{}{"a": map[string]interface{}{"nested": 1}},
			want:   map[string]interface{}{"a": map[string]interface{}{"nested": 1}},
		},
		{
			name:   "nil target allocates",
			target: nil,
			patch:  map[string]interface{}{"a": 1},
			want:   map[string]interface{}{"a": 1},
		},
		{
			name: "spec example properties patch",
			target: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"max_results":      map[string]interface{}{"type": "number", "maximum": 100},
					"include_archived": map[string]interface{}{"type": "boolean", "enum": []interface{}{true, false}},
					"query":            map[string]interface{}{"type": "string"},
				},
			},
			patch: map[string]interface{}{
				"properties": map[string]interface{}{
					"max_results":      map[string]interface{}{"maximum": 10},
					"include_archived": map[string]interface{}{"enum": []interface{}{false}},
				},
				"required": []interface{}{"query"},
			},
			want: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"max_results":      map[string]interface{}{"type": "number", "maximum": 10},
					"include_archived": map[string]interface{}{"type": "boolean", "enum": []interface{}{false}},
					"query":            map[string]interface{}{"type": "string"},
				},
				"required": []interface{}{"query"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergePatch(tt.target, tt.patch)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("mergePatch() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{
			name: "valid transform only",
			settings: map[string]any{
				"transform_tools": []any{
					map[string]any{"tool": "search_*"},
				},
			},
		},
		{
			name: "valid inject only",
			settings: map[string]any{
				"inject_tools": []any{
					map[string]any{"type": "function", "function": map[string]any{"name": "safety_check"}},
				},
			},
		},
		{
			name: "invalid scope",
			settings: map[string]any{
				"scope": "team",
				"transform_tools": []any{
					map[string]any{"tool": "search_*"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid on_conflict",
			settings: map[string]any{
				"on_conflict": "merge",
				"inject_tools": []any{
					map[string]any{"type": "function", "function": map[string]any{"name": "safety_check"}},
				},
			},
			wantErr: true,
		},
		{
			name: "inject empty function name",
			settings: map[string]any{
				"inject_tools": []any{
					map[string]any{"type": "function", "function": map[string]any{"name": ""}},
				},
			},
			wantErr: true,
		},
		{
			name: "transform empty tool",
			settings: map[string]any{
				"transform_tools": []any{
					map[string]any{"tool": ""},
				},
			},
			wantErr: true,
		},
		{
			name: "transform invalid glob",
			settings: map[string]any{
				"transform_tools": []any{
					map[string]any{"tool": "["},
				},
			},
			wantErr: true,
		},
		{
			name:     "both empty",
			settings: map[string]any{},
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.settings)
			if tt.wantErr && err == nil {
				t.Fatalf("parseConfig() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("parseConfig() error = %v, want nil", err)
			}
		})
	}
}

func TestConfigOnConflictDefault(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"inject_tools": []any{
			map[string]any{"type": "function", "function": map[string]any{"name": "safety_check"}},
		},
	})
	if err != nil {
		t.Fatalf("parseConfig() error = %v, want nil", err)
	}
	if got := cfg.onConflict(); got != conflictGatewayWins {
		t.Fatalf("onConflict() = %q, want %q", got, conflictGatewayWins)
	}
}
