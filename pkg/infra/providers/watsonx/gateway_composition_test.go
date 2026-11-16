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

package watsonx

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestGatewayComposition_AnthropicCallerToolRoundTrip(t *testing.T) {
	reg := adapter.NewRegistry()
	target := adapter.ResolveTargetFormat(provider.Watsonx, nil)
	require.Equal(t, adapter.FormatOpenAI, target)

	anthropicReq := `{
		"model": "ibm/granite-4-h-small",
		"max_tokens": 300,
		"system": "You are a weather bot.",
		"messages": [{"role": "user", "content": "Weather in Bonn?"}],
		"tools": [{"name": "get_weather", "description": "Current weather", "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}],
		"tool_choice": {"type": "tool", "name": "get_weather"}
	}`
	openAIReq, err := reg.AdaptRequestForProvider([]byte(anthropicReq), adapter.FormatAnthropic, target, provider.Watsonx, "")
	require.NoError(t, err)

	wxReq, err := buildChatRequest(openAIReq, modelChoice{}, testProject)
	require.NoError(t, err)
	got := decode(t, wxReq)
	assert.Equal(t, "ibm/granite-4-h-small", got["model_id"])
	assert.EqualValues(t, 300, got["max_tokens"])
	msgs := got["messages"].([]any)
	assert.Equal(t, map[string]any{"role": "system", "content": "You are a weather bot."}, msgs[0])
	tools := got["tools"].([]any)
	require.Len(t, tools, 1)
	assert.Equal(t, "get_weather", tools[0].(map[string]any)["function"].(map[string]any)["name"])
	assert.Equal(t, map[string]any{"type": "function", "function": map[string]any{"name": "get_weather"}}, got["tool_choice"])

	wxResp := `{"id":"chatcmpl-1","model_id":"ibm/granite-4-h-small","created":1763040000,
		"choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"chatcmpl-tool-9","type":"function","function":{"name":"get_weather","arguments":"{\"city\": \"Bonn\"}"}}]},"finish_reason":"tool_calls"}],
		"usage":{"prompt_tokens":40,"completion_tokens":12,"total_tokens":52}}`
	openAIResp, err := translateResponse([]byte(wxResp))
	require.NoError(t, err)

	anthropicResp, err := reg.AdaptResponse(openAIResp, adapter.FormatAnthropic, target)
	require.NoError(t, err)
	out := decode(t, anthropicResp)
	assert.Equal(t, "tool_use", out["stop_reason"])
	block := out["content"].([]any)[0].(map[string]any)
	assert.Equal(t, "tool_use", block["type"])
	assert.Equal(t, "chatcmpl-tool-9", block["id"])
	assert.Equal(t, "get_weather", block["name"])
	assert.Equal(t, map[string]any{"city": "Bonn"}, block["input"])
	assert.EqualValues(t, 40, out["usage"].(map[string]any)["input_tokens"])
}

func TestGatewayComposition_StreamedTextReachesAnthropicCaller(t *testing.T) {
	reg := adapter.NewRegistry()
	upstream := lines(
		"id: 1", "event: message",
		`data: {"id":"c","model_id":"ibm/granite-4-h-small","created":1,"choices":[{"index":0,"delta":{"role":"assistant","content":"Hal"}}]}`,
		"",
		"id: 2", "event: message",
		`data: {"id":"c","model_id":"ibm/granite-4-h-small","created":1,"choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`,
		"",
	)

	var text strings.Builder
	for line, err := range translateStream(upstream) {
		require.NoError(t, err)
		payload, ok := bytes.CutPrefix(line, []byte("data: "))
		if !ok || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		chunk, err := reg.DecodeStreamChunkFor(payload, adapter.FormatOpenAI)
		require.NoError(t, err)
		if chunk != nil {
			text.WriteString(chunk.Delta)
		}
	}
	assert.Equal(t, "Hallo", text.String())
}
