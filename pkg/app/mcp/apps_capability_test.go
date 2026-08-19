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

package mcp

import "testing"

func TestParseMCPAppsClientCapability(t *testing.T) {
	valid, ok := ParseMCPAppsClientCapability(map[string]any{"mimeTypes": []any{MCPAppsHTMLMIMEType, MCPAppsHTMLMIMEType}})
	if !ok || len(valid.MIMETypes) != 1 || valid.MIMETypes[0] != MCPAppsHTMLMIMEType {
		t.Fatalf("capability = %+v, %v", valid, ok)
	}
	invalid := map[string]any{
		"non-object":        "ui",
		"missing MIME list": map[string]any{},
		"empty MIME list":   map[string]any{"mimeTypes": []any{}},
		"malformed MIME":    map[string]any{"mimeTypes": []any{7}},
		"unsupported MIME":  map[string]any{"mimeTypes": []any{"text/html+skybridge"}},
		"unknown key":       map[string]any{"mimeTypes": []any{MCPAppsHTMLMIMEType}, "features": []any{"smuggled"}},
	}
	for name, declaration := range invalid {
		if got, ok := ParseMCPAppsClientCapability(declaration); ok {
			t.Errorf("%s: capability = %+v, want rejected", name, got)
		}
	}
}
