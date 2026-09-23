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
	"errors"
	"iter"
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
		{name: "anthropic client with only x_groq usage", client: adapter.FormatAnthropic, upstream: groqUpstreamLines(false, groqStreamFinishXG)},
		{name: "anthropic client with only x_groq usage and include_usage", client: adapter.FormatAnthropic, upstream: groqUpstreamLines(true, groqStreamFinishXG)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, merged := adaptGroqStream(t, tt.client, tt.upstream)
			requireGroqCacheHitUsage(t, merged)
		})
	}
}

type openAIClientChunk struct {
	Choices []json.RawMessage `json:"choices"`
	Usage   *struct {
		PromptTokens        int `json:"prompt_tokens"`
		CompletionTokens    int `json:"completion_tokens"`
		TotalTokens         int `json:"total_tokens"`
		PromptTokensDetails struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
}

func openAIClientChunks(t *testing.T, lines []string) []openAIClientChunk {
	t.Helper()
	var chunks []openAIClientChunk
	for _, line := range lines {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok || strings.TrimSpace(payload) == "[DONE]" {
			continue
		}
		var chunk openAIClientChunk
		require.NoError(t, json.Unmarshal([]byte(payload), &chunk))
		chunks = append(chunks, chunk)
	}
	return chunks
}

func TestAdaptStream_GroqOpenAIClientUsageNotDoubled(t *testing.T) {
	tests := []struct {
		name             string
		upstream         []string
		wantEmptyChoices bool
	}{
		{name: "include_usage chunk carries the usage", upstream: groqUpstreamLines(true, groqStreamFinish), wantEmptyChoices: true},
		{name: "x_groq-only finish with include_usage chunk", upstream: groqUpstreamLines(true, groqStreamFinishXG), wantEmptyChoices: true},
		{name: "finish chunk keeps the usage without include_usage chunk", upstream: groqUpstreamLines(false, groqStreamFinish)},
		{name: "x_groq-only finish keeps the usage without include_usage chunk", upstream: groqUpstreamLines(false, groqStreamFinishXG)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, _ := adaptGroqStream(t, adapter.FormatOpenAI, tt.upstream)

			require.NotEmpty(t, lines)
			assert.Equal(t, "data: [DONE]", lines[len(lines)-2], "[DONE] must stay last")
			assert.NotContains(t, strings.Join(lines, "\n"), "x_groq", "x_groq must not leak to a cross-format client")
			var usages int
			var finishes int
			for _, chunk := range openAIClientChunks(t, lines) {
				for _, choice := range chunk.Choices {
					if strings.Contains(string(choice), `"finish_reason"`) {
						finishes++
					}
				}
				if chunk.Usage == nil {
					continue
				}
				usages++
				if tt.wantEmptyChoices {
					assert.NotNil(t, chunk.Choices)
					assert.Empty(t, chunk.Choices, "the include_usage chunk must have choices: []")
				} else {
					assert.Len(t, chunk.Choices, 1, "the finish chunk must keep its choice")
				}
				assert.Equal(t, 1678, chunk.Usage.PromptTokens)
				assert.Equal(t, 32, chunk.Usage.CompletionTokens)
				assert.Equal(t, 1710, chunk.Usage.TotalTokens)
				assert.Equal(t, 1536, chunk.Usage.PromptTokensDetails.CachedTokens)
			}
			assert.Equal(t, 1, usages, "the client must receive the Groq usage exactly once")
			assert.Equal(t, 1, finishes, "the client must receive one finish")
		})
	}
}

// The OpenAI include_usage stream shape: usage is null until the trailing
// chunk with empty choices.
var openAIIncludeUsageStream = []string{
	`data: {"id":"chatcmpl-oa","object":"chat.completion.chunk","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"","refusal":null},"logprobs":null,"finish_reason":null}],"usage":null}`,
	`data: {"id":"chatcmpl-oa","object":"chat.completion.chunk","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"Hi"},"logprobs":null,"finish_reason":null}],"usage":null}`,
	`data: {"id":"chatcmpl-oa","object":"chat.completion.chunk","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"stop"}],"usage":null}`,
	`data: {"id":"chatcmpl-oa","object":"chat.completion.chunk","created":1,"model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":1,"total_tokens":10,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":0}}}`,
	"data: [DONE]",
}

func TestAdaptStream_OpenAIIncludeUsageStreamUnchanged(t *testing.T) {
	t.Run("openai upstream passes through byte-exact", func(t *testing.T) {
		lines := collectLines(t, adaptStream(linesSeq(openAIIncludeUsageStream...), adapter.NewRegistry(), adapter.FormatOpenAI, adapter.FormatOpenAI, slog.Default(), nil))
		assert.Equal(t, openAIIncludeUsageStream, lines)
	})
	t.Run("re-encoded stream keeps one usage chunk with empty choices", func(t *testing.T) {
		lines := collectLines(t, adaptStream(linesSeq(openAIIncludeUsageStream...), adapter.NewRegistry(), adapter.FormatOpenAI, adapter.FormatGroq, slog.Default(), nil))
		var usages int
		for _, chunk := range openAIClientChunks(t, lines) {
			if chunk.Usage == nil {
				continue
			}
			usages++
			assert.NotNil(t, chunk.Choices)
			assert.Empty(t, chunk.Choices)
			assert.Equal(t, 10, chunk.Usage.TotalTokens)
		}
		assert.Equal(t, 1, usages)
	})
}

func TestAdaptStream_GroqAnthropicClientGetsOneMessageDelta(t *testing.T) {
	tests := []struct {
		name         string
		includeUsage bool
		finish       string
	}{
		{name: "with include_usage", includeUsage: true, finish: groqStreamFinish},
		{name: "without include_usage", finish: groqStreamFinish},
		{name: "x_groq-only finish with include_usage", includeUsage: true, finish: groqStreamFinishXG},
		{name: "x_groq-only finish without include_usage", finish: groqStreamFinishXG},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, _ := adaptGroqStream(t, adapter.FormatAnthropic, groqUpstreamLines(tt.includeUsage, tt.finish))

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

// OpenRouter shapes: the finish chunk may repeat the usage, and some providers
// send the include_usage chunk with a role delta and an empty content.
const (
	openRouterStreamText        = `data: {"id":"gen-1","object":"chat.completion.chunk","model":"openai/gpt-4o-mini","provider":"OpenAI","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"},"finish_reason":null}]}`
	openRouterStreamUsageJSON   = `{"prompt_tokens":9,"completion_tokens":1,"total_tokens":10,"prompt_tokens_details":{"cached_tokens":4}}`
	openRouterStreamFinish      = `data: {"id":"gen-1","object":"chat.completion.chunk","model":"openai/gpt-4o-mini","provider":"OpenAI","choices":[{"index":0,"delta":{"content":""},"finish_reason":"stop","native_finish_reason":"stop"}]}`
	openRouterStreamFinishUsage = `data: {"id":"gen-1","object":"chat.completion.chunk","model":"openai/gpt-4o-mini","provider":"OpenAI","choices":[{"index":0,"delta":{"content":""},"finish_reason":"stop","native_finish_reason":"stop"}],"usage":` + openRouterStreamUsageJSON + `}`
	openRouterStreamRoleUsage   = `data: {"id":"gen-1","object":"chat.completion.chunk","model":"openai/gpt-4o-mini","provider":"OpenAI","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null,"native_finish_reason":null}],"usage":` + openRouterStreamUsageJSON + `}`
	openRouterStreamUsage       = `data: {"id":"gen-1","object":"chat.completion.chunk","model":"openai/gpt-4o-mini","provider":"OpenAI","choices":[],"usage":` + openRouterStreamUsageJSON + `}`
	upstreamErrorOnlyPayload    = `data: {"error":{"message":"transient upstream hiccup","code":500}}`
)

type clientUsageSummary struct {
	usages       int
	finishes     int
	emptyChoices int
	roles        int
	usageChunk   openAIClientChunk
	usageFinish  bool
}

func summarizeClientUsage(t *testing.T, lines []string) clientUsageSummary {
	t.Helper()
	var s clientUsageSummary
	for _, chunk := range openAIClientChunks(t, lines) {
		finish := false
		for _, choice := range chunk.Choices {
			if strings.Contains(string(choice), `"finish_reason"`) {
				finish = true
				s.finishes++
			}
			if strings.Contains(string(choice), `"role"`) {
				s.roles++
			}
		}
		if chunk.Choices != nil && len(chunk.Choices) == 0 {
			s.emptyChoices++
		}
		if chunk.Usage != nil {
			s.usages++
			s.usageChunk = chunk
			s.usageFinish = finish
		}
	}
	return s
}

func TestAdaptStream_MistralClientUsageOnlyChunkKeepsItsChoice(t *testing.T) {
	lines := collectLines(t, adaptStream(linesSeq(openAIIncludeUsageStream...), adapter.NewRegistry(), adapter.FormatMistral, adapter.FormatOpenAI, slog.Default(), nil))

	s := summarizeClientUsage(t, lines)
	assert.Zero(t, s.emptyChoices, "a Mistral client must not get choices: []")
	require.Equal(t, 1, s.usages)
	assert.Len(t, s.usageChunk.Choices, 1)
	assert.Equal(t, 10, s.usageChunk.Usage.TotalTokens)
}

func TestAdaptStream_MistralClientGetsUsageOnTheFinish(t *testing.T) {
	tests := []struct {
		name       string
		upstream   adapter.Format
		lines      []string
		wantPrompt int
		wantTotal  int
		wantCached int
	}{
		{name: "groq with include_usage", upstream: adapter.FormatGroq, lines: groqUpstreamLines(true, groqStreamFinish), wantPrompt: 1678, wantTotal: 1710, wantCached: 1536},
		{name: "groq without include_usage", upstream: adapter.FormatGroq, lines: groqUpstreamLines(false, groqStreamFinish), wantPrompt: 1678, wantTotal: 1710, wantCached: 1536},
		{name: "groq x_groq-only finish with include_usage", upstream: adapter.FormatGroq, lines: groqUpstreamLines(true, groqStreamFinishXG), wantPrompt: 1678, wantTotal: 1710, wantCached: 1536},
		{
			name: "openrouter usage chunk after the finish", upstream: adapter.FormatOpenRouter,
			lines:      []string{openRouterStreamText, openRouterStreamFinish, openRouterStreamUsage, "data: [DONE]"},
			wantPrompt: 9, wantTotal: 10, wantCached: 4,
		},
		{
			name: "openrouter role-bearing usage chunk after the finish", upstream: adapter.FormatOpenRouter,
			lines:      []string{openRouterStreamText, openRouterStreamFinish, openRouterStreamRoleUsage, "data: [DONE]"},
			wantPrompt: 9, wantTotal: 10, wantCached: 4,
		},
		{
			name: "openrouter finish with usage then a role-bearing usage chunk", upstream: adapter.FormatOpenRouter,
			lines:      []string{openRouterStreamText, openRouterStreamFinishUsage, openRouterStreamRoleUsage, "data: [DONE]"},
			wantPrompt: 9, wantTotal: 10, wantCached: 4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := collectLines(t, adaptStream(linesSeq(tt.lines...), adapter.NewRegistry(), adapter.FormatMistral, tt.upstream, slog.Default(), nil))

			joined := strings.Join(lines, "\n")
			assert.NotContains(t, joined, "x_groq")
			s := summarizeClientUsage(t, lines)
			assert.Zero(t, s.emptyChoices, "a Mistral client must not get choices: []")
			assert.Equal(t, 1, s.finishes)
			assert.Equal(t, 1, s.roles, "only the first chunk carries the role")
			require.Equal(t, 1, s.usages, "the client must receive the usage exactly once")
			assert.True(t, s.usageFinish, "the usage must ride on the finish chunk")
			assert.Equal(t, tt.wantPrompt, s.usageChunk.Usage.PromptTokens)
			assert.Equal(t, tt.wantTotal, s.usageChunk.Usage.TotalTokens)
			assert.Equal(t, tt.wantCached, s.usageChunk.Usage.PromptTokensDetails.CachedTokens)
		})
	}
}

func TestAdaptStream_OpenAIClientFoldsRoleBearingUsageChunk(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
	}{
		{name: "held finish with usage", lines: []string{openRouterStreamText, openRouterStreamFinishUsage, openRouterStreamRoleUsage, "data: [DONE]"}},
		{name: "finish without usage", lines: []string{openRouterStreamText, openRouterStreamFinish, openRouterStreamRoleUsage, "data: [DONE]"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := collectLines(t, adaptStream(linesSeq(tt.lines...), adapter.NewRegistry(), adapter.FormatOpenAI, adapter.FormatOpenRouter, slog.Default(), nil))

			assert.Equal(t, "data: [DONE]", lines[len(lines)-2])
			s := summarizeClientUsage(t, lines)
			assert.Equal(t, 1, s.finishes)
			assert.Equal(t, 1, s.roles, "the usage chunk must not repeat the role after the finish")
			require.Equal(t, 1, s.usages, "the client must receive the usage exactly once")
			assert.False(t, s.usageFinish)
			assert.NotNil(t, s.usageChunk.Choices)
			assert.Empty(t, s.usageChunk.Choices, "the usage chunk must have choices: []")
			assert.Equal(t, 10, s.usageChunk.Usage.TotalTokens)
			assert.Equal(t, 4, s.usageChunk.Usage.PromptTokensDetails.CachedTokens)
		})
	}
}

func heldFinishClients() []adapter.Format {
	return []adapter.Format{adapter.FormatOpenAI, adapter.FormatMistral}
}

func linesThenError(err error, lines ...string) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, l := range lines {
			if !yield([]byte(l), nil) {
				return
			}
		}
		yield(nil, err)
	}
}

func TestAdaptStream_HeldFinishFlushedBeforeRawError(t *testing.T) {
	for _, client := range heldFinishClients() {
		t.Run(string(client), func(t *testing.T) {
			upstreamErr := errors.New("upstream reset")
			seq := adaptStream(linesThenError(upstreamErr, groqStreamRole, groqStreamFinish), adapter.NewRegistry(), client, adapter.FormatGroq, slog.Default(), nil)

			lines, err := collectLinesAndError(seq)
			require.Error(t, err)
			assert.Same(t, upstreamErr, err, "the raw error must reach the caller unwrapped")
			var notified *ClientNotifiedStreamError
			assert.False(t, errors.As(err, &notified))
			s := summarizeClientUsage(t, lines)
			assert.Equal(t, 1, s.finishes, "the held finish must be emitted once before the error")
			assert.Equal(t, 1, s.usages)
			assert.True(t, s.usageFinish)
			assert.NotContains(t, strings.Join(lines, "\n"), "[DONE]")
		})
	}
}

func TestAdaptStream_HeldFinishFlushedWhenUpstreamEndsWithoutDone(t *testing.T) {
	for _, client := range heldFinishClients() {
		t.Run(string(client), func(t *testing.T) {
			lines := collectLines(t, adaptStream(linesSeq(groqStreamRole, groqStreamReasoning, groqStreamFinish), adapter.NewRegistry(), client, adapter.FormatGroq, slog.Default(), nil))

			assert.NotContains(t, strings.Join(lines, "\n"), "[DONE]", "no [DONE] the upstream did not send")
			s := summarizeClientUsage(t, lines)
			assert.Equal(t, 1, s.finishes)
			require.Equal(t, 1, s.usages)
			assert.True(t, s.usageFinish)
			assert.Equal(t, 1710, s.usageChunk.Usage.TotalTokens)
		})
	}
}

func TestAdaptStream_ConsumerStopsOnFlushedFinish(t *testing.T) {
	upstreams := []struct {
		name string
		seq  func() iter.Seq2[[]byte, error]
	}{
		{name: "flushed on [DONE]", seq: func() iter.Seq2[[]byte, error] { return linesSeq(groqUpstreamLines(false, groqStreamFinish)...) }},
		{name: "flushed on include_usage chunk", seq: func() iter.Seq2[[]byte, error] { return linesSeq(groqUpstreamLines(true, groqStreamFinish)...) }},
		{name: "flushed on upstream end", seq: func() iter.Seq2[[]byte, error] { return linesSeq(groqStreamRole, groqStreamFinish) }},
		{name: "flushed on raw error", seq: func() iter.Seq2[[]byte, error] {
			return linesThenError(errors.New("upstream reset"), groqStreamRole, groqStreamFinish)
		}},
		{name: "flushed on a later content chunk", seq: func() iter.Seq2[[]byte, error] {
			return linesSeq(groqStreamRole, groqStreamFinish, groqStreamReasoning, "data: [DONE]")
		}},
	}
	for _, client := range heldFinishClients() {
		for _, up := range upstreams {
			t.Run(string(client)+" "+up.name, func(t *testing.T) {
				var afterStop int
				stopped := false
				for line, err := range adaptStream(up.seq(), adapter.NewRegistry(), client, adapter.FormatGroq, slog.Default(), nil) {
					if stopped {
						afterStop++
						continue
					}
					require.NoError(t, err)
					if strings.Contains(string(line), `"finish_reason"`) {
						stopped = true
						break
					}
				}
				assert.True(t, stopped, "the consumer must see the flushed finish")
				assert.Zero(t, afterStop)
			})
		}
	}
}

func TestAdaptStream_UpstreamErrorOnlyPayloadBetweenFinishAndUsage(t *testing.T) {
	upstream := []string{groqStreamRole, groqStreamFinish, upstreamErrorOnlyPayload, groqStreamTrailing, "data: [DONE]"}
	tests := []struct {
		client          adapter.Format
		wantUsageFinish bool
	}{
		{client: adapter.FormatOpenAI},
		{client: adapter.FormatMistral, wantUsageFinish: true},
	}
	for _, tt := range tests {
		t.Run(string(tt.client), func(t *testing.T) {
			lines := collectLines(t, adaptStream(linesSeq(upstream...), adapter.NewRegistry(), tt.client, adapter.FormatGroq, slog.Default(), nil))

			assert.NotContains(t, strings.Join(lines, "\n"), "transient upstream hiccup")
			s := summarizeClientUsage(t, lines)
			assert.Equal(t, 1, s.finishes)
			require.Equal(t, 1, s.usages, "the error-only payload must not break the usage fold")
			assert.Equal(t, tt.wantUsageFinish, s.usageFinish)
			assert.Equal(t, 1710, s.usageChunk.Usage.TotalTokens)
		})
	}
}
