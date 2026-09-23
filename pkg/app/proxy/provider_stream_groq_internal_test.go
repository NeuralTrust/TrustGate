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

package proxy

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Trimmed from a live openai/gpt-oss-120b cache-hit stream captured for
// ENG-1618 (ids removed): usage rides on the finish chunk twice, top level and
// in x_groq.usage, and include_usage repeats it in a trailing chunk.
const (
	groqStreamRole      = `data: {"id":"chatcmpl-groq","object":"chat.completion.chunk","model":"openai/gpt-oss-120b","choices":[{"index":0,"delta":{"role":"assistant","content":""},"logprobs":null,"finish_reason":null}],"x_groq":{"seed":1049072006}}`
	groqStreamReasoning = `data: {"id":"chatcmpl-groq","object":"chat.completion.chunk","model":"openai/gpt-oss-120b","choices":[{"index":0,"delta":{"reasoning":"The","channel":"analysis"},"logprobs":null,"finish_reason":null}]}`
	groqStreamUsageJSON = `{"queue_time":0.214502734,"prompt_tokens":1678,"prompt_time":0.013016579,"completion_tokens":32,"completion_time":0.068478021,"total_tokens":1710,"total_time":0.0814946,"prompt_tokens_details":{"cached_tokens":1536},"completion_tokens_details":{"reasoning_tokens":30}}`
	groqStreamFinish    = `data: {"id":"chatcmpl-groq","object":"chat.completion.chunk","model":"openai/gpt-oss-120b","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"length"}],"x_groq":{"usage":` + groqStreamUsageJSON + `},"usage":` + groqStreamUsageJSON + `}`
	groqStreamFinishXG  = `data: {"id":"chatcmpl-groq","object":"chat.completion.chunk","model":"openai/gpt-oss-120b","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"length"}],"x_groq":{"usage":` + groqStreamUsageJSON + `}}`
	groqStreamTrailing  = `data: {"id":"chatcmpl-groq","object":"chat.completion.chunk","model":"openai/gpt-oss-120b","choices":[],"usage":` + groqStreamUsageJSON + `,"service_tier":"on_demand"}`
)

func groqUpstreamLines(includeUsage bool, finish string) []string {
	lines := []string{groqStreamRole, groqStreamReasoning, finish}
	if includeUsage {
		lines = append(lines, groqStreamTrailing)
	}
	return append(lines, "data: [DONE]")
}

func adaptGroqStream(t *testing.T, client adapter.Format, upstream []string) ([]string, *adapter.CanonicalUsage) {
	t.Helper()
	var merged *adapter.CanonicalUsage
	observe := func(c *adapter.CanonicalStreamChunk) { merged = adapter.MergeUsage(merged, c.Usage) }
	lines := collectLines(t, adaptStream(linesSeq(upstream...), adapter.NewRegistry(), client, adapter.FormatGroq, slog.Default(), observe))
	return lines, merged
}

func requireGroqCacheHitUsage(t *testing.T, u *adapter.CanonicalUsage) {
	t.Helper()
	require.NotNil(t, u, "observer must see the Groq stream usage")
	assert.Equal(t, 1678, u.InputTokens)
	assert.Equal(t, 32, u.OutputTokens)
	assert.Equal(t, 1710, u.TotalTokens)
	assert.Equal(t, 1536, u.CachedInputTokens)
	assert.Equal(t, 30, u.ReasoningOutputTokens)
}

func TestAdaptStream_GroqUsageReachesObserver(t *testing.T) {
	tests := []struct {
		name     string
		client   adapter.Format
		upstream []string
	}{
		{name: "openai client with include_usage", client: adapter.FormatOpenAI, upstream: groqUpstreamLines(true, groqStreamFinish)},
		{name: "openai client without include_usage", client: adapter.FormatOpenAI, upstream: groqUpstreamLines(false, groqStreamFinish)},
		{name: "openai client with only x_groq usage", client: adapter.FormatOpenAI, upstream: groqUpstreamLines(false, groqStreamFinishXG)},
		{name: "anthropic client with include_usage", client: adapter.FormatAnthropic, upstream: groqUpstreamLines(true, groqStreamFinish)},
		{name: "anthropic client without include_usage", client: adapter.FormatAnthropic, upstream: groqUpstreamLines(false, groqStreamFinish)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, merged := adaptGroqStream(t, tt.client, tt.upstream)
			requireGroqCacheHitUsage(t, merged)
		})
	}
}

func TestAdaptStream_GroqOpenAIClientUsageNotDoubled(t *testing.T) {
	lines, _ := adaptGroqStream(t, adapter.FormatOpenAI, groqUpstreamLines(true, groqStreamFinish))

	assert.Contains(t, lines, "data: [DONE]")
	var usages int
	for _, line := range lines {
		assert.NotContains(t, line, "x_groq", "x_groq must not leak to a cross-format client")
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok || strings.TrimSpace(payload) == "[DONE]" {
			continue
		}
		var chunk struct {
			Usage *struct {
				PromptTokens        int `json:"prompt_tokens"`
				CompletionTokens    int `json:"completion_tokens"`
				TotalTokens         int `json:"total_tokens"`
				PromptTokensDetails struct {
					CachedTokens int `json:"cached_tokens"`
				} `json:"prompt_tokens_details"`
			} `json:"usage"`
		}
		require.NoError(t, json.Unmarshal([]byte(payload), &chunk))
		if chunk.Usage == nil {
			continue
		}
		usages++
		assert.Equal(t, 1678, chunk.Usage.PromptTokens)
		assert.Equal(t, 32, chunk.Usage.CompletionTokens)
		assert.Equal(t, 1710, chunk.Usage.TotalTokens)
		assert.Equal(t, 1536, chunk.Usage.PromptTokensDetails.CachedTokens)
	}
	assert.Positive(t, usages, "the client must receive the Groq usage")
}

func TestAdaptStream_GroqAnthropicClientGetsOneMessageDelta(t *testing.T) {
	tests := []struct {
		name         string
		includeUsage bool
	}{
		{name: "with include_usage", includeUsage: true},
		{name: "without include_usage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, _ := adaptGroqStream(t, adapter.FormatAnthropic, groqUpstreamLines(tt.includeUsage, groqStreamFinish))

			joined := strings.Join(lines, "\n")
			assert.NotContains(t, joined, "x_groq")
			_, events := typedEvents(t, lines)
			delta := eventOfType(t, events, "message_delta")
			assert.JSONEq(t, `{"input_tokens":142,"output_tokens":32,"cache_read_input_tokens":1536}`, string(delta.Usage))
			assert.Contains(t, joined, `"stop_reason":"max_tokens"`)
			eventOfType(t, events, "message_stop")
		})
	}
}
