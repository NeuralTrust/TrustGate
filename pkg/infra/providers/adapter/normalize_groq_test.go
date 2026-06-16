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

package adapter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeGroqRequest_SetsParallelToolCallsFalse(t *testing.T) {
	input := `{
		"model": "llama-3.3-70b-versatile",
		"tools": [{"function": {"name": "search", "parameters": {"type": "object"}}}],
		"messages": [{"role": "user", "content": "hi"}]
	}`
	out := NormalizeGroqRequest([]byte(input))
	var raw map[string]any
	require.NoError(t, json.Unmarshal(out, &raw))
	assert.Equal(t, false, raw["parallel_tool_calls"])
}

func TestNormalizeGroqRequest_InjectsToolType(t *testing.T) {
	input := `{
		"model": "llama-3.3-70b-versatile",
		"tools": [{"function": {"name": "search", "parameters": {"type": "object"}}}],
		"messages": [{"role": "user", "content": "hi"}]
	}`
	out := NormalizeGroqRequest([]byte(input))
	var raw struct {
		Tools []struct {
			Type string `json:"type"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(out, &raw))
	require.Len(t, raw.Tools, 1)
	assert.Equal(t, "function", raw.Tools[0].Type)
}

func TestNormalizeGroqRequest_StripsLlamaFunctionOnlyAssistantTurn(t *testing.T) {
	input := `{
		"model": "llama-3.3-70b-versatile",
		"tools": [{"type": "function", "function": {"name": "db", "parameters": {"type": "object"}}}],
		"messages": [
			{"role": "user", "content": "hola"},
			{"role": "assistant", "content": "<function=database_agent{\"q\":\"x\"}</function>"},
			{"role": "user", "content": "retry"}
		]
	}`
	out := NormalizeGroqRequest([]byte(input))
	var raw struct {
		Messages []struct {
			Role string `json:"role"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(out, &raw))
	require.Len(t, raw.Messages, 2)
	assert.Equal(t, "user", raw.Messages[0].Role)
	assert.Equal(t, "user", raw.Messages[1].Role)
}

func TestNormalizeRequestForProvider_GroqUsesGroqNormalizer(t *testing.T) {
	input := `{
		"model": "meta-llama/llama-4-scout-17b-16e-instruct",
		"tools": [{"function": {"name": "search", "parameters": {"type": "object"}}}],
		"messages": [{"role": "user", "content": "hi"}]
	}`
	out := NormalizeRequestForProvider("groq", FormatGroq, []byte(input))
	var raw map[string]any
	require.NoError(t, json.Unmarshal(out, &raw))
	assert.Equal(t, false, raw["parallel_tool_calls"])
}

func TestNormalizeGroqRequest_PreservesAssistantWithToolCalls(t *testing.T) {
	input := `{
		"model": "llama-3.3-70b-versatile",
		"tools": [{"type": "function", "function": {"name": "db", "parameters": {"type": "object"}}}],
		"messages": [
			{"role": "assistant", "content": null, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "db", "arguments": "{}"}}]}
		]
	}`
	out := NormalizeGroqRequest([]byte(input))
	var raw struct {
		Messages []struct {
			Role string `json:"role"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(out, &raw))
	require.Len(t, raw.Messages, 1)
	assert.Equal(t, "assistant", raw.Messages[0].Role)
}
