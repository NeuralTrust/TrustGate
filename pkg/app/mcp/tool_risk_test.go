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

import (
	"context"
	"encoding/json"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

func toolFrom(t *testing.T, raw string) Tool {
	t.Helper()
	var tool Tool
	if err := json.Unmarshal([]byte(raw), &tool); err != nil {
		t.Fatalf("decode tool: %v", err)
	}
	return tool
}

func TestToolRisk(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		raw       string
		risk      string
		openWorld *bool
	}{
		{name: "no annotations", raw: `{"name":"a"}`},
		{name: "title only is unannotated", raw: `{"name":"a","annotations":{"title":"A"}}`},
		{name: "malformed annotations", raw: `{"name":"a","annotations":"yes"}`},
		{name: "read only", raw: `{"name":"a","annotations":{"readOnlyHint":true,"openWorldHint":false}}`, risk: ToolRiskReadOnly, openWorld: new(false)},
		{name: "read only wins over destructive", raw: `{"name":"a","annotations":{"readOnlyHint":true,"destructiveHint":true}}`, risk: ToolRiskReadOnly, openWorld: new(true)},
		{name: "writes default to destructive", raw: `{"name":"a","annotations":{"readOnlyHint":false}}`, risk: ToolRiskDestructive, openWorld: new(true)},
		{name: "any hint makes the defaults apply", raw: `{"name":"a","annotations":{"idempotentHint":true}}`, risk: ToolRiskDestructive, openWorld: new(true)},
		{name: "explicitly destructive", raw: `{"name":"a","annotations":{"destructiveHint":true,"openWorldHint":true}}`, risk: ToolRiskDestructive, openWorld: new(true)},
		{name: "additive", raw: `{"name":"a","annotations":{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":false}}`, risk: ToolRiskAdditive, openWorld: new(false)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			risk, openWorld := toolFrom(t, tt.raw).Risk()
			if risk != tt.risk {
				t.Fatalf("risk = %q, want %q", risk, tt.risk)
			}
			if (openWorld == nil) != (tt.openWorld == nil) || (openWorld != nil && *openWorld != *tt.openWorld) {
				t.Fatalf("openWorld = %v, want %v", openWorld, tt.openWorld)
			}
		})
	}
}

func TestComposer_Invoke_StampsToolRisk(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	up := &fakeUpstream{tools: tools("delete_repo"), result: json.RawMessage(`{"content":[]}`)}
	c := newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": up}})
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg)

	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanMCP, "tools/call")
	ctx := trace.NewSpanContext(context.Background(), span)

	target := &ResolvedTool{Registry: reg, Tool: toolFrom(t, `{"name":"delete_repo","annotations":{"destructiveHint":true,"openWorldHint":false}}`)}
	if _, err := c.Invoke(ctx, rc, target, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	attrs, ok := span.MCPAttrsCopy()
	if !ok || attrs.ToolRisk != ToolRiskDestructive || attrs.ToolOpenWorld == nil || *attrs.ToolOpenWorld {
		t.Fatalf("span = %+v, want destructive and closed world", attrs)
	}
}
