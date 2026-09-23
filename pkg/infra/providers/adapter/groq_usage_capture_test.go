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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Trimmed from a live openai/gpt-oss-120b stream (cache hit, max_tokens 32,
// stream_options.include_usage) captured for ENG-1618; ids removed.
const (
	groqCaptureFinishBoth = `{"object":"chat.completion.chunk","model":"openai/gpt-oss-120b","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"length"}],` +
		`"x_groq":{"usage":{"queue_time":0.214502734,"prompt_tokens":1678,"prompt_time":0.013016579,"completion_tokens":32,"completion_time":0.068478021,"total_tokens":1710,"total_time":0.0814946,"prompt_tokens_details":{"cached_tokens":1536},"completion_tokens_details":{"reasoning_tokens":30}}},` +
		`"usage":{"queue_time":0.214502734,"prompt_tokens":1678,"prompt_time":0.013016579,"completion_tokens":32,"completion_time":0.068478021,"total_tokens":1710,"total_time":0.0814946,"prompt_tokens_details":{"cached_tokens":1536},"completion_tokens_details":{"reasoning_tokens":30}}}`
	groqCaptureFinishXGroqOnly = `{"object":"chat.completion.chunk","model":"openai/gpt-oss-120b","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"length"}],` +
		`"x_groq":{"usage":{"queue_time":0.214502734,"prompt_tokens":1678,"prompt_time":0.013016579,"completion_tokens":32,"completion_time":0.068478021,"total_tokens":1710,"total_time":0.0814946,"prompt_tokens_details":{"cached_tokens":1536},"completion_tokens_details":{"reasoning_tokens":30}}}}`
	groqCaptureIncludeUsage = `{"object":"chat.completion.chunk","model":"openai/gpt-oss-120b","choices":[],` +
		`"usage":{"queue_time":0.214502734,"prompt_tokens":1678,"prompt_time":0.013016579,"completion_tokens":32,"completion_time":0.068478021,"total_tokens":1710,"total_time":0.0814946,"prompt_tokens_details":{"cached_tokens":1536},"completion_tokens_details":{"reasoning_tokens":30}},"service_tier":"on_demand"}`
	groqCaptureFinishNoCache = `{"object":"chat.completion.chunk","model":"openai/gpt-oss-120b","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"length"}],` +
		`"x_groq":{"usage":{"queue_time":0.152286074,"prompt_tokens":1702,"prompt_time":0.087556678,"completion_tokens":64,"completion_time":0.140797528,"total_tokens":1766,"total_time":0.228354206,"completion_tokens_details":{"reasoning_tokens":62}}},` +
		`"usage":{"queue_time":0.152286074,"prompt_tokens":1702,"prompt_time":0.087556678,"completion_tokens":64,"completion_time":0.140797528,"total_tokens":1766,"total_time":0.228354206,"completion_tokens_details":{"reasoning_tokens":62}}}`
	groqBufferedBoth = `{"object":"chat.completion","model":"openai/gpt-oss-120b","choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"length"}],` +
		`"usage":{"queue_time":0.2,"prompt_tokens":1678,"completion_tokens":32,"total_tokens":1710,"prompt_tokens_details":{"cached_tokens":1536},"completion_tokens_details":{"reasoning_tokens":30}},` +
		`"x_groq":{"usage":{"prompt_tokens":1678,"completion_tokens":32,"total_tokens":1710,"prompt_tokens_details":{"cached_tokens":1536},"completion_tokens_details":{"reasoning_tokens":30}}}}`
	groqBufferedXGroqOnly = `{"object":"chat.completion","model":"openai/gpt-oss-120b","choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"length"}],` +
		`"x_groq":{"usage":{"prompt_tokens":1678,"completion_tokens":32,"total_tokens":1710,"prompt_tokens_details":{"cached_tokens":1536},"completion_tokens_details":{"reasoning_tokens":30}}}}`
	groqStreamStandardSmaller = `{"object":"chat.completion.chunk","model":"openai/gpt-oss-120b","choices":[{"index":0,"delta":{},"finish_reason":"length"}],` +
		`"usage":{"prompt_tokens":1678,"completion_tokens":20,"total_tokens":1698},` +
		`"x_groq":{"usage":{"prompt_tokens":1678,"completion_tokens":32,"total_tokens":1710,"prompt_tokens_details":{"cached_tokens":1536},"completion_tokens_details":{"reasoning_tokens":30}}}}`
)

func groqCacheHitUsage() CanonicalUsage {
	return CanonicalUsage{
		InputTokens:           1678,
		OutputTokens:          32,
		TotalTokens:           1710,
		CachedInputTokens:     1536,
		ReasoningOutputTokens: 30,
	}
}

func assertUsage(t *testing.T, want CanonicalUsage, got *CanonicalUsage) {
	t.Helper()
	require.NotNil(t, got)
	assert.Equal(t, want.InputTokens, got.InputTokens, "input")
	assert.Equal(t, want.OutputTokens, got.OutputTokens, "output")
	assert.Equal(t, want.TotalTokens, got.TotalTokens, "total")
	assert.Equal(t, want.CachedInputTokens, got.CachedInputTokens, "cache read")
	assert.Equal(t, want.CacheWriteInputTokens, got.CacheWriteInputTokens, "cache write")
	assert.Equal(t, want.ReasoningOutputTokens, got.ReasoningOutputTokens, "reasoning")
}

func TestGroqCapture_StreamUsage(t *testing.T) {
	noCache := CanonicalUsage{InputTokens: 1702, OutputTokens: 64, TotalTokens: 1766, ReasoningOutputTokens: 62}
	tests := []struct {
		name       string
		chunk      string
		want       CanonicalUsage
		wantFinish string
	}{
		{name: "finish chunk with both usage copies counts once", chunk: groqCaptureFinishBoth, want: groqCacheHitUsage(), wantFinish: "length"},
		{name: "finish chunk with only x_groq usage", chunk: groqCaptureFinishXGroqOnly, want: groqCacheHitUsage(), wantFinish: "length"},
		{name: "include_usage chunk with empty choices", chunk: groqCaptureIncludeUsage, want: groqCacheHitUsage()},
		{name: "finish chunk without cache hit", chunk: groqCaptureFinishNoCache, want: noCache, wantFinish: "length"},
		{name: "standard and x_groq usage merge by max", chunk: groqStreamStandardSmaller, want: groqCacheHitUsage(), wantFinish: "length"},
	}
	a := groqAdapter(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, err := a.DecodeStreamChunk([]byte(tt.chunk))
			require.NoError(t, err)
			require.NotNil(t, sc)
			assertUsage(t, tt.want, sc.Usage)
			assert.Equal(t, tt.wantFinish, sc.FinishReason)
		})
	}
}

func TestGroqCapture_StreamMergeAcrossChunks(t *testing.T) {
	a := groqAdapter(t)
	var merged *CanonicalUsage
	for _, chunk := range []string{groqCaptureFinishBoth, groqCaptureIncludeUsage} {
		sc, err := a.DecodeStreamChunk([]byte(chunk))
		require.NoError(t, err)
		require.NotNil(t, sc)
		merged = MergeUsage(merged, sc.Usage)
	}
	assertUsage(t, groqCacheHitUsage(), merged)
	assert.Equal(t, 1678-1536, merged.PlainInputTokens())
}

func TestGroqCapture_BufferedUsage(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "usage and x_groq usage count once", body: groqBufferedBoth},
		{name: "only x_groq usage", body: groqBufferedXGroqOnly},
	}
	a := groqAdapter(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := a.DecodeResponse([]byte(tt.body))
			require.NoError(t, err)
			assertUsage(t, groqCacheHitUsage(), cr.Usage)
		})
	}
}

func TestGroqCapture_TimingOnlyXGroqUsageAddsNoTokens(t *testing.T) {
	a := groqAdapter(t)
	cr, err := a.DecodeResponse([]byte(groqResponseWithXGroq))
	require.NoError(t, err)
	assertUsage(t, CanonicalUsage{InputTokens: 10, OutputTokens: 5, TotalTokens: 15}, cr.Usage)
}
