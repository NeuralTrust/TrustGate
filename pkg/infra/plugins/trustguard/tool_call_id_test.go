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

package trustguard

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// attributesOf is the attributes object of a body as TrustGuard receives it.
func attributesOf(t *testing.T, wire any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(wire)
	require.NoError(t, err)
	var doc struct {
		Attributes map[string]any `json:"attributes"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	return doc.Attributes
}

// The agent's tool call id reaches TrustGuard as attributes.tool.call_id on both request shapes, so a
// call checked by the agent's hook and by the gateway can be counted once.
func TestToolCallIDReachesTrustGuard(t *testing.T) {
	t.Parallel()
	mcpCall := func(id string) *infracontext.RequestContext {
		return &infracontext.RequestContext{MCP: true, MCPServerName: "Gmail", MCPTool: "list_labels", MCPToolCallID: id}
	}
	llmCall := &infracontext.RequestContext{RequestedModel: "gpt-4o", Provider: "openai", MCPToolCallID: "call_1",
		Body: []byte(`{"model":"gpt-4o","messages":[]}`)}

	tests := []struct {
		name string
		req  *infracontext.RequestContext
		want any // attributes.tool, nil when absent
	}{
		{name: "mcp call with an id", req: mcpCall("call_abc123"), want: map[string]any{"call_id": "call_abc123"}},
		{name: "mcp call without an id", req: mcpCall(""), want: nil},
		{name: "llm call", req: llmCall, want: nil},
		{name: "no request context", req: nil, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := GuardRequest{
				Direction:  "input",
				Protocol:   "mcp",
				Attributes: GuardAttributes{MCPServer: &GuardMCPServer{ID: "reg-1", Code: "gmail"}},
				request:    tt.req,
			}
			for shape, wire := range map[string]any{"v1": withInventory(body), "v2": toV2Request(body, tt.req)} {
				attrs := attributesOf(t, wire)
				if tt.want == nil {
					assert.NotContains(t, attrs, "tool", shape)
					continue
				}
				assert.Equal(t, tt.want, attrs["tool"], shape)
			}
			assert.Nil(t, body.Attributes.ToolCall, "the caller's copy is untouched")
		})
	}
}
