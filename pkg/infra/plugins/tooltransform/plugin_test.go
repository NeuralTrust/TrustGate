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
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func strptr(s string) *string { return &s }

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

func TestMergePatchDoesNotAliasPatch(t *testing.T) {
	patchNested := map[string]interface{}{"k": "v"}
	patch := map[string]interface{}{"props": patchNested}

	got := mergePatch(map[string]interface{}{"type": "object"}, patch)

	gotNested, ok := got["props"].(map[string]interface{})
	if !ok {
		t.Fatalf("got[\"props\"] is not an object: %#v", got["props"])
	}
	gotNested["k"] = "mutated"
	gotNested["added"] = "x"

	if patchNested["k"] != "v" {
		t.Fatalf("patch nested value mutated: %v", patchNested["k"])
	}
	if _, exists := patchNested["added"]; exists {
		t.Fatalf("patch nested map gained a key from mutating the result")
	}

	if reflect.ValueOf(got["props"]).Pointer() == reflect.ValueOf(patch["props"]).Pointer() {
		t.Fatalf("missing-target case aliased patch nested map")
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

func TestMatchToolPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		tool    string
		want    bool
	}{
		{name: "star match", pattern: "search_*", tool: "search_docs", want: true},
		{name: "star no match", pattern: "search_*", tool: "send_email", want: false},
		{name: "single char match", pattern: "tool_?", tool: "tool_1", want: true},
		{name: "single char no match", pattern: "tool_?", tool: "tool_12", want: false},
		{name: "class match", pattern: "tool_[abc]", tool: "tool_b", want: true},
		{name: "class no match", pattern: "tool_[abc]", tool: "tool_d", want: false},
		{name: "slash via sentinel match", pattern: "ns/*", tool: "ns/search", want: true},
		{name: "slash literal match", pattern: "ns/search", tool: "ns/search", want: true},
		{name: "invalid pattern", pattern: "[", tool: "anything", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchToolPattern(tt.pattern, tt.tool); got != tt.want {
				t.Fatalf("matchToolPattern(%q, %q) = %v, want %v", tt.pattern, tt.tool, got, tt.want)
			}
		})
	}
}

func TestApplyTransforms(t *testing.T) {
	tests := []struct {
		name        string
		tools       []adapter.CanonicalTool
		entries     []transformDef
		wantChanged bool
		wantTools   []adapter.CanonicalTool
	}{
		{
			name: "single match patches schema and description",
			tools: []adapter.CanonicalTool{
				{Name: "search_docs", Description: "old", Schema: map[string]interface{}{"type": "object"}},
			},
			entries: []transformDef{
				{
					Tool:                "search_*",
					SchemaPatch:         map[string]interface{}{"title": "x"},
					DescriptionOverride: strptr("new"),
				},
			},
			wantChanged: true,
			wantTools: []adapter.CanonicalTool{
				{Name: "search_docs", Description: "new", Schema: map[string]interface{}{"type": "object", "title": "x"}},
			},
		},
		{
			name: "no match untouched",
			tools: []adapter.CanonicalTool{
				{Name: "send_email", Description: "keep", Schema: map[string]interface{}{"type": "object"}},
			},
			entries: []transformDef{
				{Tool: "search_*", SchemaPatch: map[string]interface{}{"title": "x"}, DescriptionOverride: strptr("new")},
			},
			wantChanged: false,
			wantTools: []adapter.CanonicalTool{
				{Name: "send_email", Description: "keep", Schema: map[string]interface{}{"type": "object"}},
			},
		},
		{
			name: "cumulative patches and last description wins",
			tools: []adapter.CanonicalTool{
				{Name: "search_logs", Description: "old", Schema: map[string]interface{}{"type": "object"}},
			},
			entries: []transformDef{
				{Tool: "search_*", SchemaPatch: map[string]interface{}{"a": 1}, DescriptionOverride: strptr("first")},
				{Tool: "search_logs", SchemaPatch: map[string]interface{}{"b": 2}, DescriptionOverride: strptr("second")},
			},
			wantChanged: true,
			wantTools: []adapter.CanonicalTool{
				{Name: "search_logs", Description: "second", Schema: map[string]interface{}{"type": "object", "a": 1, "b": 2}},
			},
		},
		{
			name: "description only entry nil schema patch",
			tools: []adapter.CanonicalTool{
				{Name: "search_docs", Description: "old", Schema: map[string]interface{}{"type": "object"}},
			},
			entries: []transformDef{
				{Tool: "search_*", DescriptionOverride: strptr("new")},
			},
			wantChanged: true,
			wantTools: []adapter.CanonicalTool{
				{Name: "search_docs", Description: "new", Schema: map[string]interface{}{"type": "object"}},
			},
		},
		{
			name: "schema only entry nil description override",
			tools: []adapter.CanonicalTool{
				{Name: "search_docs", Description: "keep", Schema: map[string]interface{}{"type": "object"}},
			},
			entries: []transformDef{
				{Tool: "search_*", SchemaPatch: map[string]interface{}{"title": "x"}},
			},
			wantChanged: true,
			wantTools: []adapter.CanonicalTool{
				{Name: "search_docs", Description: "keep", Schema: map[string]interface{}{"type": "object", "title": "x"}},
			},
		},
		{
			name: "schema patch allocates nil schema",
			tools: []adapter.CanonicalTool{
				{Name: "search_docs"},
			},
			entries: []transformDef{
				{Tool: "search_*", SchemaPatch: map[string]interface{}{"title": "x"}},
			},
			wantChanged: true,
			wantTools: []adapter.CanonicalTool{
				{Name: "search_docs", Schema: map[string]interface{}{"title": "x"}},
			},
		},
		{
			name: "empty schema patch nil description override no change",
			tools: []adapter.CanonicalTool{
				{Name: "search_docs", Description: "keep", Schema: map[string]interface{}{"type": "object"}},
			},
			entries: []transformDef{
				{Tool: "search_*", SchemaPatch: map[string]interface{}{}},
			},
			wantChanged: false,
			wantTools: []adapter.CanonicalTool{
				{Name: "search_docs", Description: "keep", Schema: map[string]interface{}{"type": "object"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := applyTransforms(tt.tools, tt.entries)
			if changed != tt.wantChanged {
				t.Fatalf("applyTransforms() changed = %v, want %v", changed, tt.wantChanged)
			}
			if !reflect.DeepEqual(tt.tools, tt.wantTools) {
				t.Fatalf("applyTransforms() tools = %#v, want %#v", tt.tools, tt.wantTools)
			}
		})
	}
}

func injectFn(name, desc string) injectDef {
	return injectDef{Type: "function", Function: fnDef{Name: name, Description: desc}}
}

func TestApplyInjections(t *testing.T) {
	tests := []struct {
		name         string
		tools        []adapter.CanonicalTool
		entries      []injectDef
		conflict     string
		wantErr      bool
		wantRejected string
		wantTools    []adapter.CanonicalTool
		wantOutcomes []injectOutcome
	}{
		{
			name:     "no collision append",
			tools:    []adapter.CanonicalTool{{Name: "search_docs", Description: "client"}},
			entries:  []injectDef{injectFn("safety_check", "g")},
			conflict: conflictGatewayWins,
			wantTools: []adapter.CanonicalTool{
				{Name: "search_docs", Description: "client"},
				{Name: "safety_check", Description: "g"},
			},
			wantOutcomes: []injectOutcome{{Name: "safety_check", Outcome: outcomeAppended}},
		},
		{
			name:     "client name collision gateway wins replaces in place",
			tools:    []adapter.CanonicalTool{{Name: "safety_check", Description: "client"}, {Name: "other", Description: "o"}},
			entries:  []injectDef{injectFn("safety_check", "gateway")},
			conflict: conflictGatewayWins,
			wantTools: []adapter.CanonicalTool{
				{Name: "safety_check", Description: "gateway"},
				{Name: "other", Description: "o"},
			},
			wantOutcomes: []injectOutcome{{Name: "safety_check", Outcome: outcomeReplaced}},
		},
		{
			name:     "client name collision client wins drops",
			tools:    []adapter.CanonicalTool{{Name: "safety_check", Description: "client"}},
			entries:  []injectDef{injectFn("safety_check", "gateway")},
			conflict: conflictClientWins,
			wantTools: []adapter.CanonicalTool{
				{Name: "safety_check", Description: "client"},
			},
			wantOutcomes: []injectOutcome{{Name: "safety_check", Outcome: outcomeDropped}},
		},
		{
			name:         "client name collision reject errors",
			tools:        []adapter.CanonicalTool{{Name: "safety_check", Description: "client"}},
			entries:      []injectDef{injectFn("safety_check", "gateway")},
			conflict:     conflictReject,
			wantErr:      true,
			wantRejected: "safety_check",
		},
		{
			name:     "injected duplicate gateway wins keeps later",
			tools:    []adapter.CanonicalTool{},
			entries:  []injectDef{injectFn("dup", "first"), injectFn("dup", "second")},
			conflict: conflictGatewayWins,
			wantTools: []adapter.CanonicalTool{
				{Name: "dup", Description: "second"},
			},
			wantOutcomes: []injectOutcome{
				{Name: "dup", Outcome: outcomeAppended},
				{Name: "dup", Outcome: outcomeReplaced},
			},
		},
		{
			name:     "injected duplicate client wins keeps earlier",
			tools:    []adapter.CanonicalTool{},
			entries:  []injectDef{injectFn("dup", "first"), injectFn("dup", "second")},
			conflict: conflictClientWins,
			wantTools: []adapter.CanonicalTool{
				{Name: "dup", Description: "first"},
			},
			wantOutcomes: []injectOutcome{
				{Name: "dup", Outcome: outcomeAppended},
				{Name: "dup", Outcome: outcomeDropped},
			},
		},
		{
			name:         "injected duplicate reject errors with name",
			tools:        []adapter.CanonicalTool{},
			entries:      []injectDef{injectFn("dup", "first"), injectFn("dup", "second")},
			conflict:     conflictReject,
			wantErr:      true,
			wantRejected: "dup",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, outcomes, err := applyInjections(tt.tools, tt.entries, tt.conflict)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("applyInjections() error = nil, want error")
				}
				pe, ok := appplugins.AsPluginError(err)
				if !ok {
					t.Fatalf("applyInjections() error is not *PluginError: %v", err)
				}
				if pe.StatusCode != http.StatusBadRequest {
					t.Fatalf("StatusCode = %d, want %d", pe.StatusCode, http.StatusBadRequest)
				}
				var decoded map[string]any
				if uerr := json.Unmarshal(pe.Body, &decoded); uerr != nil {
					t.Fatalf("json.Unmarshal(Body) error = %v", uerr)
				}
				errObj, ok := decoded["error"].(map[string]any)
				if !ok {
					t.Fatalf("reject body missing error object: %#v", decoded)
				}
				if errObj["name"] != tt.wantRejected {
					t.Fatalf("reject name = %v, want %q", errObj["name"], tt.wantRejected)
				}
				if got != nil || outcomes != nil {
					t.Fatalf("applyInjections() on reject = (%v, %v), want (nil, nil)", got, outcomes)
				}
				return
			}
			if err != nil {
				t.Fatalf("applyInjections() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(got, tt.wantTools) {
				t.Fatalf("applyInjections() tools = %#v, want %#v", got, tt.wantTools)
			}
			if !reflect.DeepEqual(outcomes, tt.wantOutcomes) {
				t.Fatalf("applyInjections() outcomes = %#v, want %#v", outcomes, tt.wantOutcomes)
			}
		})
	}
}

func TestApplyInjectionsEmptyConflictDefaultsGatewayWins(t *testing.T) {
	cfg := &config{}
	tools := []adapter.CanonicalTool{{Name: "safety_check", Description: "client"}}
	got, outcomes, err := applyInjections(tools, []injectDef{injectFn("safety_check", "gateway")}, cfg.onConflict())
	if err != nil {
		t.Fatalf("applyInjections() error = %v, want nil", err)
	}
	wantTools := []adapter.CanonicalTool{{Name: "safety_check", Description: "gateway"}}
	if !reflect.DeepEqual(got, wantTools) {
		t.Fatalf("applyInjections() tools = %#v, want %#v", got, wantTools)
	}
	wantOutcomes := []injectOutcome{{Name: "safety_check", Outcome: outcomeReplaced}}
	if !reflect.DeepEqual(outcomes, wantOutcomes) {
		t.Fatalf("applyInjections() outcomes = %#v, want %#v", outcomes, wantOutcomes)
	}
}

func TestRejectErrorBodyExactness(t *testing.T) {
	err := rejectError("safety_check")
	pe, ok := appplugins.AsPluginError(err)
	if !ok {
		t.Fatalf("rejectError() is not *PluginError: %v", err)
	}
	if pe.StatusCode != http.StatusBadRequest {
		t.Fatalf("StatusCode = %d, want %d", pe.StatusCode, http.StatusBadRequest)
	}
	if pe.Type != "tool_name_reserved" {
		t.Fatalf("Type = %q, want %q", pe.Type, "tool_name_reserved")
	}
	wantBytes, merr := json.Marshal(map[string]any{
		"error": map[string]any{"type": "tool_name_reserved", "name": "safety_check"},
	})
	if merr != nil {
		t.Fatalf("json.Marshal(expected) error = %v", merr)
	}
	var gotMap, wantMap map[string]any
	if uerr := json.Unmarshal(pe.Body, &gotMap); uerr != nil {
		t.Fatalf("json.Unmarshal(Body) error = %v", uerr)
	}
	if uerr := json.Unmarshal(wantBytes, &wantMap); uerr != nil {
		t.Fatalf("json.Unmarshal(expected) error = %v", uerr)
	}
	if !reflect.DeepEqual(gotMap, wantMap) {
		t.Fatalf("reject body = %#v, want %#v", gotMap, wantMap)
	}
}

func openAIReqBody(t *testing.T, toolName string) []byte {
	t.Helper()
	body := map[string]any{
		"model":    "gpt",
		"user":     "abc",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
		"tools": []any{
			map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        toolName,
					"description": "original",
					"parameters":  map[string]any{"type": "object"},
				},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal(body) error = %v", err)
	}
	return b
}

func findTool(tools []adapter.CanonicalTool, name string) (adapter.CanonicalTool, bool) {
	for i := range tools {
		if tools[i].Name == name {
			return tools[i], true
		}
	}
	return adapter.CanonicalTool{}, false
}

func TestPluginPreRequestPipelineSmoke(t *testing.T) {
	p := New(adapter.NewRegistry())
	settings := map[string]any{
		"transform_tools": []any{
			map[string]any{
				"tool":                 "search_*",
				"schema_patch":         map[string]any{"title": "patched"},
				"description_override": "overridden",
			},
		},
		"inject_tools": []any{
			map[string]any{
				"type":     "function",
				"function": map[string]any{"name": "safety_check", "description": "gateway"},
			},
		},
	}
	in := appplugins.ExecInput{
		Stage:   policy.StagePreRequest,
		Config:  policy.PluginConfig{ID: "tt-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Scope:   appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"},
		Request: &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: openAIReqBody(t, "search_docs")},
	}

	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("Execute() error = %v, want nil", err)
	}
	if res == nil || res.RequestBody == nil {
		t.Fatalf("Execute() result = %#v, want non-nil RequestBody", res)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}

	decoded, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
	if err != nil {
		t.Fatalf("DecodeRequestFor(RequestBody) error = %v", err)
	}

	transformed, ok := findTool(decoded.Tools, "search_docs")
	if !ok {
		t.Fatalf("decoded tools missing search_docs: %#v", decoded.Tools)
	}
	if transformed.Description != "overridden" {
		t.Fatalf("search_docs description = %q, want %q", transformed.Description, "overridden")
	}
	if transformed.Schema["title"] != "patched" {
		t.Fatalf("search_docs schema title = %v, want %q", transformed.Schema["title"], "patched")
	}
	if transformed.Schema["type"] != "object" {
		t.Fatalf("search_docs schema type = %v, want %q", transformed.Schema["type"], "object")
	}

	if _, ok := findTool(decoded.Tools, "safety_check"); !ok {
		t.Fatalf("decoded tools missing injected safety_check: %#v", decoded.Tools)
	}
}

func TestPluginPreRequestNoOpSmoke(t *testing.T) {
	p := New(adapter.NewRegistry())
	settings := map[string]any{
		"inject_tools": []any{
			map[string]any{"type": "function", "function": map[string]any{"name": "safety_check"}},
		},
	}
	mkInput := func(req *infracontext.RequestContext) appplugins.ExecInput {
		return appplugins.ExecInput{
			Stage:   policy.StagePreRequest,
			Config:  policy.PluginConfig{ID: "tt-1", Slug: PluginName, Name: PluginName, Settings: settings},
			Scope:   appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"},
			Request: req,
		}
	}
	cases := []struct {
		name string
		req  *infracontext.RequestContext
	}{
		{name: "nil request", req: nil},
		{name: "nil body", req: &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: nil}},
		{name: "empty body", req: &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := p.Execute(context.Background(), mkInput(tc.req))
			if err != nil {
				t.Fatalf("Execute() error = %v, want nil", err)
			}
			if res == nil {
				t.Fatalf("Execute() result = nil, want okResult")
			}
			if res.StatusCode != http.StatusOK {
				t.Fatalf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
			}
			if res.RequestBody != nil {
				t.Fatalf("RequestBody = %q, want nil", res.RequestBody)
			}
		})
	}
}

func matrixSettings() map[string]any {
	return map[string]any{
		"transform_tools": []any{
			map[string]any{
				"tool":                 "search_*",
				"schema_patch":         map[string]any{"title": "patched"},
				"description_override": "overridden",
			},
		},
		"inject_tools": []any{
			map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        "safety_check",
					"description": "gateway",
					"parameters":  map[string]any{"type": "object"},
				},
			},
		},
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal error = %v", err)
	}
	return b
}

func openAICompletionsToolBody(t *testing.T, toolName string, params map[string]any) []byte {
	t.Helper()
	return mustMarshal(t, map[string]any{
		"model":    "gpt",
		"user":     "abc",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
		"tools": []any{
			map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        toolName,
					"description": "original",
					"parameters":  params,
				},
			},
		},
	})
}

func openAIResponsesToolBody(t *testing.T, toolName string) []byte {
	t.Helper()
	return mustMarshal(t, map[string]any{
		"model": "gpt",
		"user":  "abc",
		"input": "hi",
		"tools": []any{
			map[string]any{
				"type":        "function",
				"name":        toolName,
				"description": "original",
				"parameters":  map[string]any{"type": "object"},
			},
		},
	})
}

func anthropicToolBody(t *testing.T, toolName string) []byte {
	t.Helper()
	return mustMarshal(t, map[string]any{
		"model":      "claude",
		"system":     "be safe",
		"max_tokens": 1024,
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"tools": []any{
			map[string]any{
				"name":         toolName,
				"description":  "original",
				"input_schema": map[string]any{"type": "object"},
			},
		},
	})
}

func bedrockClaudeToolBody(t *testing.T, toolName string) []byte {
	t.Helper()
	return mustMarshal(t, map[string]any{
		"anthropic_version": "bedrock-2023-05-31",
		"system":            "be safe",
		"max_tokens":        1024,
		"messages":          []any{map[string]any{"role": "user", "content": "hi"}},
		"tools": []any{
			map[string]any{
				"name":         toolName,
				"description":  "original",
				"input_schema": map[string]any{"type": "object"},
			},
		},
	})
}

func geminiToolBody(t *testing.T, toolName string) []byte {
	t.Helper()
	return mustMarshal(t, map[string]any{
		"contents": []any{
			map[string]any{"role": "user", "parts": []any{map[string]any{"text": "hi"}}},
		},
		"cachedContent": "projects/p/cachedContents/abc",
		"tools": []any{
			map[string]any{
				"functionDeclarations": []any{
					map[string]any{
						"name":        toolName,
						"description": "original",
						"parameters":  map[string]any{"type": "OBJECT"},
					},
				},
			},
		},
	})
}

func mistralToolBody(t *testing.T, toolName string) []byte {
	t.Helper()
	return mustMarshal(t, map[string]any{
		"model":    "mistral-large",
		"user":     "abc",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
		"tools": []any{
			map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        toolName,
					"description": "original",
					"parameters":  map[string]any{"type": "object"},
				},
			},
		},
	})
}

func execPreRequest(t *testing.T, settings map[string]any, sourceFormat string, body []byte) *appplugins.Result {
	t.Helper()
	p := New(adapter.NewRegistry())
	in := appplugins.ExecInput{
		Stage:   policy.StagePreRequest,
		Config:  policy.PluginConfig{ID: "tt-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Scope:   appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"},
		Request: &infracontext.RequestContext{Provider: sourceFormat, SourceFormat: sourceFormat, Body: body},
	}
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("Execute() error = %v, want nil", err)
	}
	if res == nil || res.RequestBody == nil {
		t.Fatalf("Execute() result = %#v, want non-nil RequestBody", res)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	return res
}

func TestPluginPreRequestProviderMatrix(t *testing.T) {
	tests := []struct {
		name         string
		sourceFormat string
		decodeFormat adapter.Format
		body         []byte
		untouchedKey string
		untouchedVal any
	}{
		{
			name:         "openai completions",
			sourceFormat: string(adapter.FormatOpenAI),
			decodeFormat: adapter.FormatOpenAI,
			body:         openAICompletionsToolBody(t, "search_docs", map[string]any{"type": "object"}),
			untouchedKey: "user",
			untouchedVal: "abc",
		},
		{
			name:         "openai responses",
			sourceFormat: string(adapter.FormatOpenAIResponses),
			decodeFormat: adapter.FormatOpenAIResponses,
			body:         openAIResponsesToolBody(t, "search_docs"),
			untouchedKey: "user",
			untouchedVal: "abc",
		},
		{
			name:         "anthropic",
			sourceFormat: string(adapter.FormatAnthropic),
			decodeFormat: adapter.FormatAnthropic,
			body:         anthropicToolBody(t, "search_docs"),
			untouchedKey: "system",
			untouchedVal: "be safe",
		},
		{
			name:         "gemini",
			sourceFormat: string(adapter.FormatGemini),
			decodeFormat: adapter.FormatGemini,
			body:         geminiToolBody(t, "search_docs"),
			untouchedKey: "cachedContent",
			untouchedVal: "projects/p/cachedContents/abc",
		},
		{
			name:         "bedrock claude",
			sourceFormat: string(adapter.FormatBedrock),
			decodeFormat: adapter.FormatBedrock,
			body:         bedrockClaudeToolBody(t, "search_docs"),
			untouchedKey: "system",
			untouchedVal: "be safe",
		},
		{
			name:         "mistral",
			sourceFormat: string(adapter.FormatMistral),
			decodeFormat: adapter.FormatMistral,
			body:         mistralToolBody(t, "search_docs"),
			untouchedKey: "user",
			untouchedVal: "abc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := execPreRequest(t, matrixSettings(), tt.sourceFormat, tt.body)

			decoded, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, tt.decodeFormat)
			if err != nil {
				t.Fatalf("DecodeRequestFor(RequestBody) error = %v", err)
			}

			transformed, ok := findTool(decoded.Tools, "search_docs")
			if !ok {
				t.Fatalf("decoded tools missing search_docs: %#v", decoded.Tools)
			}
			if transformed.Description != "overridden" {
				t.Fatalf("search_docs description = %q, want %q", transformed.Description, "overridden")
			}
			if transformed.Schema["title"] != "patched" {
				t.Fatalf("search_docs schema title = %v, want %q", transformed.Schema["title"], "patched")
			}
			if transformed.Schema["type"] != "object" {
				t.Fatalf("search_docs schema type = %v, want %q", transformed.Schema["type"], "object")
			}

			if _, ok := findTool(decoded.Tools, "safety_check"); !ok {
				t.Fatalf("decoded tools missing injected safety_check: %#v", decoded.Tools)
			}

			var raw map[string]any
			if uerr := json.Unmarshal(res.RequestBody, &raw); uerr != nil {
				t.Fatalf("json.Unmarshal(RequestBody) error = %v", uerr)
			}
			if got := raw[tt.untouchedKey]; !reflect.DeepEqual(got, tt.untouchedVal) {
				t.Fatalf("untouched field %q = %#v, want %#v", tt.untouchedKey, got, tt.untouchedVal)
			}
		})
	}
}

func toolSet(tools []adapter.CanonicalTool) map[string]adapter.CanonicalTool {
	m := make(map[string]adapter.CanonicalTool, len(tools))
	for i := range tools {
		m[tools[i].Name] = tools[i]
	}
	return m
}

func TestPluginCrossProviderEquivalence(t *testing.T) {
	settings := matrixSettings()

	openAIRes := execPreRequest(t, settings, string(adapter.FormatOpenAI), openAICompletionsToolBody(t, "search_docs", map[string]any{"type": "object"}))
	anthropicRes := execPreRequest(t, settings, string(adapter.FormatAnthropic), anthropicToolBody(t, "search_docs"))

	reg := adapter.NewRegistry()
	openAIDecoded, err := reg.DecodeRequestFor(openAIRes.RequestBody, adapter.FormatOpenAI)
	if err != nil {
		t.Fatalf("DecodeRequestFor(openai) error = %v", err)
	}
	anthropicDecoded, err := reg.DecodeRequestFor(anthropicRes.RequestBody, adapter.FormatAnthropic)
	if err != nil {
		t.Fatalf("DecodeRequestFor(anthropic) error = %v", err)
	}

	if !reflect.DeepEqual(toolSet(openAIDecoded.Tools), toolSet(anthropicDecoded.Tools)) {
		t.Fatalf("cross-provider tool sets differ:\nopenai=%#v\nanthropic=%#v", openAIDecoded.Tools, anthropicDecoded.Tools)
	}
}

func TestPluginInjectAfterTransformOrdering(t *testing.T) {
	t.Run("injected tool appended after transformed tools", func(t *testing.T) {
		res := execPreRequest(t, matrixSettings(), string(adapter.FormatOpenAI), openAICompletionsToolBody(t, "search_docs", map[string]any{"type": "object"}))
		decoded, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
		if err != nil {
			t.Fatalf("DecodeRequestFor error = %v", err)
		}
		if len(decoded.Tools) != 2 {
			t.Fatalf("decoded tools = %#v, want 2", decoded.Tools)
		}
		if decoded.Tools[0].Name != "search_docs" {
			t.Fatalf("tools[0] = %q, want search_docs", decoded.Tools[0].Name)
		}
		if decoded.Tools[0].Description != "overridden" || decoded.Tools[0].Schema["title"] != "patched" {
			t.Fatalf("tools[0] not transformed before injection: %#v", decoded.Tools[0])
		}
		if decoded.Tools[1].Name != "safety_check" {
			t.Fatalf("tools[1] = %q, want safety_check appended last", decoded.Tools[1].Name)
		}
	})

	t.Run("injection observes post-transform tool set on collision", func(t *testing.T) {
		settings := map[string]any{
			"transform_tools": []any{
				map[string]any{
					"tool":                 "search_*",
					"schema_patch":         map[string]any{"title": "patched"},
					"description_override": "overridden",
				},
			},
			"inject_tools": []any{
				map[string]any{
					"type": "function",
					"function": map[string]any{
						"name":        "search_docs",
						"description": "gateway",
						"parameters":  map[string]any{"type": "object"},
					},
				},
			},
			"on_conflict": "gateway_wins",
		}
		res := execPreRequest(t, settings, string(adapter.FormatOpenAI), openAICompletionsToolBody(t, "search_docs", map[string]any{"type": "object"}))
		decoded, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
		if err != nil {
			t.Fatalf("DecodeRequestFor error = %v", err)
		}
		if len(decoded.Tools) != 1 {
			t.Fatalf("decoded tools = %#v, want 1 (gateway replaced post-transform tool)", decoded.Tools)
		}
		got := decoded.Tools[0]
		if got.Name != "search_docs" {
			t.Fatalf("tool name = %q, want search_docs", got.Name)
		}
		if got.Description != "gateway" {
			t.Fatalf("description = %q, want gateway (injected replaced the transformed tool)", got.Description)
		}
		if _, hasTitle := got.Schema["title"]; hasTitle {
			t.Fatalf("schema retained transform title; gateway tool should have replaced it: %#v", got.Schema)
		}
	})
}

func TestPluginExecuteNoOpMatrix(t *testing.T) {
	transformAndInject := matrixSettings()
	transformOnlyMatching := map[string]any{
		"transform_tools": []any{map[string]any{"tool": "search_*"}},
	}
	transformOnlyNoMatch := map[string]any{
		"transform_tools": []any{
			map[string]any{"tool": "nomatch_*", "description_override": "x"},
		},
	}
	noToolsBody := mustMarshal(t, map[string]any{
		"model":    "gpt",
		"user":     "abc",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	})

	tests := []struct {
		name     string
		settings map[string]any
		req      *infracontext.RequestContext
	}{
		{
			name:     "empty wire format",
			settings: transformAndInject,
			req:      &infracontext.RequestContext{Provider: "", SourceFormat: "", Body: openAICompletionsToolBody(t, "search_docs", map[string]any{"type": "object"})},
		},
		{
			name:     "undecodable body",
			settings: transformAndInject,
			req:      &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte("{not-json")},
		},
		{
			name:     "no transform matches and no inject",
			settings: transformOnlyNoMatch,
			req:      &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: openAICompletionsToolBody(t, "search_docs", map[string]any{"type": "object"})},
		},
		{
			name:     "zero tools and no inject",
			settings: transformOnlyMatching,
			req:      &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: noToolsBody},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(adapter.NewRegistry())
			in := appplugins.ExecInput{
				Stage:   policy.StagePreRequest,
				Config:  policy.PluginConfig{ID: "tt-1", Slug: PluginName, Name: PluginName, Settings: tt.settings},
				Scope:   appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"},
				Request: tt.req,
			}
			res, err := p.Execute(context.Background(), in)
			if err != nil {
				t.Fatalf("Execute() error = %v, want nil", err)
			}
			if res == nil {
				t.Fatalf("Execute() result = nil, want okResult")
			}
			if res.StatusCode != http.StatusOK {
				t.Fatalf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
			}
			if res.RequestBody != nil {
				t.Fatalf("RequestBody = %q, want nil", res.RequestBody)
			}
		})
	}
}

func TestPluginExecuteRejectPath(t *testing.T) {
	settings := map[string]any{
		"on_conflict": "reject",
		"inject_tools": []any{
			map[string]any{
				"type":     "function",
				"function": map[string]any{"name": "safety_check", "description": "gateway"},
			},
		},
	}
	p := New(adapter.NewRegistry())
	in := appplugins.ExecInput{
		Stage:   policy.StagePreRequest,
		Config:  policy.PluginConfig{ID: "tt-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Scope:   appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"},
		Request: &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: openAIReqBody(t, "safety_check")},
	}

	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("Execute() result = %#v, want nil", res)
	}
	pe, ok := appplugins.AsPluginError(err)
	if !ok {
		t.Fatalf("Execute() error is not *PluginError: %v", err)
	}
	if pe.StatusCode != http.StatusBadRequest {
		t.Fatalf("StatusCode = %d, want %d", pe.StatusCode, http.StatusBadRequest)
	}
	if pe.Type != "tool_name_reserved" {
		t.Fatalf("Type = %q, want %q", pe.Type, "tool_name_reserved")
	}
	wantBytes := mustMarshal(t, map[string]any{
		"error": map[string]any{"type": "tool_name_reserved", "name": "safety_check"},
	})
	var gotMap, wantMap map[string]any
	if uerr := json.Unmarshal(pe.Body, &gotMap); uerr != nil {
		t.Fatalf("json.Unmarshal(Body) error = %v", uerr)
	}
	if uerr := json.Unmarshal(wantBytes, &wantMap); uerr != nil {
		t.Fatalf("json.Unmarshal(expected) error = %v", uerr)
	}
	if !reflect.DeepEqual(gotMap, wantMap) {
		t.Fatalf("reject body = %#v, want %#v", gotMap, wantMap)
	}
}

func TestPluginNestedSchemaPatchDecodeGuard(t *testing.T) {
	settings := map[string]any{
		"transform_tools": []any{
			map[string]any{
				"tool": "search_*",
				"schema_patch": map[string]any{
					"properties": map[string]any{
						"max_results": map[string]any{"maximum": 10},
					},
				},
			},
		},
	}
	params := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"max_results": map[string]any{"type": "number", "maximum": 100},
		},
	}
	res := execPreRequest(t, settings, string(adapter.FormatOpenAI), openAICompletionsToolBody(t, "search_docs", params))

	decoded, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
	if err != nil {
		t.Fatalf("DecodeRequestFor error = %v", err)
	}
	tool, ok := findTool(decoded.Tools, "search_docs")
	if !ok {
		t.Fatalf("decoded tools missing search_docs: %#v", decoded.Tools)
	}
	props, ok := tool.Schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("schema.properties not an object: %#v", tool.Schema["properties"])
	}
	maxResults, ok := props["max_results"].(map[string]interface{})
	if !ok {
		t.Fatalf("schema.properties.max_results not an object: %#v", props["max_results"])
	}
	if maxResults["maximum"] != float64(10) {
		t.Fatalf("nested patch not applied: maximum = %v, want 10", maxResults["maximum"])
	}
	if maxResults["type"] != "number" {
		t.Fatalf("sibling nested key lost: type = %v, want number", maxResults["type"])
	}
}
