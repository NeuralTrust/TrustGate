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
	"fmt"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bp(ttl CacheTTL) *CanonicalCacheBreakpoint {
	return &CanonicalCacheBreakpoint{TTL: ttl}
}

func ttlOf(b *CanonicalCacheBreakpoint) any {
	if b == nil {
		return nil
	}
	return b.TTL
}

func messageTTLs(msgs []CanonicalMessage) []any {
	out := make([]any, len(msgs))
	for i := range msgs {
		out[i] = ttlOf(msgs[i].Cache)
	}
	return out
}

func toolTTLs(tools []CanonicalTool) []any {
	out := make([]any, len(tools))
	for i := range tools {
		out[i] = ttlOf(tools[i].Cache)
	}
	return out
}

func cachedRequest(tools, msgs int, ttl CacheTTL) *CanonicalRequest {
	req := &CanonicalRequest{System: "sys", SystemCache: bp(ttl)}
	for i := 0; i < tools; i++ {
		req.Tools = append(req.Tools, CanonicalTool{Name: "t", Cache: bp(ttl)})
	}
	for i := 0; i < msgs; i++ {
		req.Messages = append(req.Messages, CanonicalMessage{Role: "user", Content: "m", Cache: bp(ttl)})
	}
	return req
}

func TestNormalizeCacheIntent_KeepsTheLastBreakpointsWithinTheLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		req       *CanonicalRequest
		wantTools []any
		wantMsgs  []any
	}{
		{
			name:      "one tool, system and four messages keep the last two messages",
			req:       cachedRequest(1, 4, ""),
			wantTools: []any{CacheTTL("")},
			wantMsgs:  []any{nil, nil, CacheTTL(""), CacheTTL("")},
		},
		{
			name:      "tools drop once messages are down to their last breakpoint",
			req:       cachedRequest(3, 3, ""),
			wantTools: []any{nil, CacheTTL(""), CacheTTL("")},
			wantMsgs:  []any{nil, nil, CacheTTL("")},
		},
		{
			name:      "four breakpoints are left alone",
			req:       cachedRequest(1, 2, ""),
			wantTools: []any{CacheTTL("")},
			wantMsgs:  []any{CacheTTL(""), CacheTTL("")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			normalizeCacheIntent(tt.req, FormatAnthropic, formatProvider(FormatAnthropic), "")
			assert.Equal(t, tt.wantTools, toolTTLs(tt.req.Tools))
			assert.Equal(t, tt.wantMsgs, messageTTLs(tt.req.Messages))
			assert.NotNil(t, tt.req.SystemCache)
		})
	}
}

func TestNormalizeCacheIntent_AutoCountsTowardTheLimit(t *testing.T) {
	t.Parallel()

	req := cachedRequest(1, 3, "")
	req.CacheOptions = &CanonicalCacheOptions{Auto: bp("")}
	normalizeCacheIntent(req, FormatAnthropic, formatProvider(FormatAnthropic), "")

	assert.Equal(t, []any{nil, nil, CacheTTL("")}, messageTTLs(req.Messages))
	require.NotNil(t, req.CacheOptions)
	assert.NotNil(t, req.CacheOptions.Auto)
}

func TestNormalizeCacheIntent_OneHourNeverFollowsAShorterTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		target     Format
		toolTTL    CacheTTL
		systemTTL  CacheTTL
		messageTTL CacheTTL
		want       [3]CacheTTL
	}{
		{name: "system 5m, message 1h", target: FormatAnthropic, toolTTL: CacheTTL1h, systemTTL: CacheTTL5m, messageTTL: CacheTTL1h, want: [3]CacheTTL{CacheTTL1h, CacheTTL5m, CacheTTL5m}},
		{name: "bedrock follows the same order", target: FormatBedrock, toolTTL: CacheTTL1h, systemTTL: CacheTTL5m, messageTTL: CacheTTL1h, want: [3]CacheTTL{CacheTTL1h, CacheTTL5m, CacheTTL5m}},
		{name: "a default TTL counts as short", target: FormatAnthropic, toolTTL: "", systemTTL: CacheTTL1h, messageTTL: CacheTTL1h, want: [3]CacheTTL{"", CacheTTL5m, CacheTTL5m}},
		{name: "1h throughout stays 1h", target: FormatAnthropic, toolTTL: CacheTTL1h, systemTTL: CacheTTL1h, messageTTL: CacheTTL1h, want: [3]CacheTTL{CacheTTL1h, CacheTTL1h, CacheTTL1h}},
		{name: "1h before 5m stays", target: FormatAnthropic, toolTTL: CacheTTL1h, systemTTL: CacheTTL1h, messageTTL: CacheTTL5m, want: [3]CacheTTL{CacheTTL1h, CacheTTL1h, CacheTTL5m}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := &CanonicalRequest{
				System:      "sys",
				SystemCache: bp(tt.systemTTL),
				Tools:       []CanonicalTool{{Name: "t", Cache: bp(tt.toolTTL)}},
				Messages:    []CanonicalMessage{{Role: "user", Content: "m", Cache: bp(tt.messageTTL)}},
			}
			normalizeCacheIntent(req, tt.target, formatProvider(tt.target), "")
			assert.Equal(t, tt.want, [3]CacheTTL{req.Tools[0].Cache.TTL, req.SystemCache.TTL, req.Messages[0].Cache.TTL})
		})
	}
}

func TestNormalizeCacheIntent_TargetsWithoutCachingDropAllIntent(t *testing.T) {
	t.Parallel()

	for _, target := range []Format{FormatGemini, FormatVertex, FormatGroq, FormatCohere, FormatDeepSeek, FormatXAI} {
		t.Run(string(target), func(t *testing.T) {
			t.Parallel()
			req := cachedRequest(1, 2, CacheTTL1h)
			req.CacheOptions = &CanonicalCacheOptions{Key: "k", Retention: "24h", Mode: "explicit", Options: json.RawMessage(`{}`), Auto: bp("")}
			normalizeCacheIntent(req, target, formatProvider(target), "")

			assert.Nil(t, req.SystemCache)
			assert.Nil(t, req.CacheOptions)
			assert.Equal(t, []any{nil}, toolTTLs(req.Tools))
			assert.Equal(t, []any{nil, nil}, messageTTLs(req.Messages))
		})
	}
}

func TestNormalizeCacheIntent_BedrockKeepsAutoAndDropsRequestOptions(t *testing.T) {
	t.Parallel()

	req := cachedRequest(0, 1, CacheTTL1h)
	req.CacheOptions = &CanonicalCacheOptions{Key: "k", Retention: "24h", Auto: bp("")}
	normalizeCacheIntent(req, FormatBedrock, formatProvider(FormatBedrock), "")

	assert.Equal(t, &CanonicalCacheOptions{Auto: bp("")}, req.CacheOptions)
	assert.Equal(t, CacheTTL1h, req.SystemCache.TTL)
	assert.Equal(t, []any{CacheTTL1h}, messageTTLs(req.Messages))
}

func TestNormalizeCacheIntent_NoIntentIsANoOp(t *testing.T) {
	t.Parallel()

	normalizeCacheIntent(nil, FormatAnthropic, formatProvider(FormatAnthropic), "")
	req := &CanonicalRequest{System: "s", Messages: []CanonicalMessage{{Role: "user", Content: "hi"}}, Tools: []CanonicalTool{{Name: "t"}}}
	want := *req
	normalizeCacheIntent(req, FormatAnthropic, formatProvider(FormatAnthropic), "")
	assert.Equal(t, want, *req)
}

func TestAdaptRequest_AnthropicCacheIntentIsDroppedForTargetsWithoutCaching(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"model": "claude-sonnet-4-5",
		"max_tokens": 64,
		"cache_control": {"type": "ephemeral"},
		"system": [{"type": "text", "text": "Long prefix.", "cache_control": {"type": "ephemeral", "ttl": "1h"}}],
		"tools": [{"name": "lookup", "input_schema": {"type": "object"}, "cache_control": {"type": "ephemeral"}}],
		"messages": [{"role": "user", "content": [{"type": "text", "text": "hi", "cache_control": {"type": "ephemeral"}}]}]
	}`)
	reg := NewRegistry()
	for _, target := range []Format{FormatGemini, FormatGroq, FormatCohere, FormatOpenAI, FormatOpenAIResponses} {
		t.Run(string(target), func(t *testing.T) {
			t.Parallel()
			out, err := reg.AdaptRequest(body, FormatAnthropic, target)
			require.NoError(t, err)
			assert.NotContains(t, string(out), "cache")
			assert.Contains(t, string(out), "Long prefix.")
		})
	}
}

func TestAdaptRequest_AnthropicSystemTextIsByteStableAcrossClientFormats(t *testing.T) {
	t.Parallel()

	const system = "  You are terse.\n\n"
	anthropicBody, err := json.Marshal(map[string]any{
		"model":      "openai/gpt-oss-120b",
		"max_tokens": 64,
		"system":     system,
		"messages":   []map[string]any{{"role": "user", "content": "hi"}},
	})
	require.NoError(t, err)
	openaiBody, err := json.Marshal(map[string]any{
		"model":      "openai/gpt-oss-120b",
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "system", "content": system}, {"role": "user", "content": "hi"}},
	})
	require.NoError(t, err)

	reg := NewRegistry()
	fromAnthropic, err := reg.AdaptRequest(anthropicBody, FormatAnthropic, FormatGroq)
	require.NoError(t, err)
	fromOpenAI, err := reg.AdaptRequest(openaiBody, FormatOpenAI, FormatGroq)
	require.NoError(t, err)

	systemOf := func(body []byte) string {
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		require.NoError(t, json.Unmarshal(body, &req))
		require.NotEmpty(t, req.Messages)
		require.Equal(t, "system", req.Messages[0].Role)
		return req.Messages[0].Content
	}
	assert.Equal(t, system, systemOf(fromAnthropic))
	assert.Equal(t, systemOf(fromOpenAI), systemOf(fromAnthropic))
}

func TestNormalizeCacheIntent_DroppedBreakpointsDoNotDowngradeTheRest(t *testing.T) {
	t.Parallel()

	req := &CanonicalRequest{
		System:      "s",
		SystemCache: bp(CacheTTL1h),
		Tools:       []CanonicalTool{{Name: "t", Cache: bp(CacheTTL1h)}},
		Messages: []CanonicalMessage{
			{Role: "user", Content: "a", Cache: bp(CacheTTL5m)},
			{Role: "assistant", Content: "b", Cache: bp(CacheTTL1h)},
			{Role: "user", Content: "c", Cache: bp(CacheTTL1h)},
		},
	}
	normalizeCacheIntent(req, FormatAnthropic, formatProvider(FormatAnthropic), "")

	assert.Equal(t, []any{nil, CacheTTL1h, CacheTTL1h}, messageTTLs(req.Messages))
	assert.Equal(t, CacheTTL1h, req.SystemCache.TTL)
}

func TestNormalizeCacheIntent_KeepsTheTextBoundary(t *testing.T) {
	t.Parallel()

	boundary := CanonicalCacheBreakpoint{TTL: CacheTTL1h, inText: true, newlines: 1}
	sys := boundary
	req := &CanonicalRequest{
		System:      "a\nb",
		SystemCache: &sys,
		Messages:    []CanonicalMessage{{Role: "user", Content: "m", Cache: bp("")}},
	}
	normalizeCacheIntent(req, FormatAnthropic, formatProvider(FormatAnthropic), "")
	assert.Equal(t, &boundary, req.SystemCache)
}

func TestLaterCacheBreakpoint_ReturnsACopy(t *testing.T) {
	t.Parallel()

	earlier, later := bp(CacheTTL1h), &CanonicalCacheBreakpoint{inText: true, newline: 2}
	merged := laterCacheBreakpoint(earlier, later)
	assert.Equal(t, &CanonicalCacheBreakpoint{TTL: CacheTTL1h, inText: true, newline: 2}, merged)
	assert.Equal(t, &CanonicalCacheBreakpoint{inText: true, newline: 2}, later)
	assert.Equal(t, bp(CacheTTL1h), earlier)
	assert.Same(t, earlier, laterCacheBreakpoint(earlier, nil))
}

func TestIsGPT56OrLater(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"gpt-5.6":                             true,
		"gpt-5.6-mini":                        true,
		"gpt-5.6-2026-08-01":                  true,
		"openai/gpt-5.7":                      true,
		"GPT-5.10":                            true,
		"gpt-6":                               true,
		"gpt-6.1-codex":                       true,
		"gpt-5.5":                             false,
		"gpt-5":                               false,
		"gpt-5-mini":                          false,
		"gpt-5.1-codex":                       false,
		"gpt-4o":                              false,
		"gpt-4.1":                             false,
		"gpt-oss-120b":                        false,
		"o3":                                  false,
		"claude-sonnet-4-5":                   false,
		"":                                    false,
		"openai/gpt-5.5-turbo":                false,
		"my-gpt-5.6-deployment":               false,
		"gpt-35-turbo":                        false,
		"gpt-35-turbo-16k":                    false,
		"gpt-10":                              true,
		"gpt-10.1-mini":                       true,
		"gpt-12-2027-01-01":                   true,
		"gpt-50":                              true,
		"gpt-10o":                             false,
		"gpt-05":                              false,
		"gpt-100":                             false,
		"ft:gpt-5.6-mini:acme:support:abc123": true,
		"FT:GPT-5.6:acme::abc":                true,
		"ft:gpt-4o-mini:acme::abc":            false,
		"gpt-5.6:free":                        true,
		"openai/ft:gpt-5.6:org::id":           true,
		"azure/ft:gpt-4o:org::id":             false,
	}
	for model, want := range tests {
		t.Run(model, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, want, isGPT56OrLater(model))
		})
	}
}

func TestNormalizeCacheIntent_OpenAIFamilyKeysFollowTheProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		target   Format
		provider string
		model    string
		want     *CanonicalCacheOptions
	}{
		{name: "openai before gpt-5.6 keeps retention", target: FormatOpenAI, provider: provider.OpenAI, model: "gpt-4o", want: &CanonicalCacheOptions{Key: "k", Retention: "24h"}},
		{name: "openai gpt-5.6 keeps options", target: FormatOpenAI, provider: provider.OpenAI, model: "gpt-5.6", want: &CanonicalCacheOptions{Key: "k", Options: json.RawMessage(`{"ttl":"30m"}`)}},
		{name: "responses before gpt-5.6", target: FormatOpenAIResponses, provider: provider.OpenAI, model: "gpt-4o", want: &CanonicalCacheOptions{Key: "k", Retention: "24h"}},
		{name: "azure chat keeps retention", target: FormatAzure, provider: provider.Azure, model: "gpt-4.1", want: &CanonicalCacheOptions{Key: "k", Retention: "24h"}},
		{name: "azure deployment name keeps retention", target: FormatAzure, provider: provider.Azure, model: "prod-chat", want: &CanonicalCacheOptions{Key: "k", Retention: "24h"}},
		{name: "azure deployment named like gpt-5.6 sends only the key", target: FormatAzure, provider: provider.Azure, model: "gpt-5.6", want: &CanonicalCacheOptions{Key: "k"}},
		{name: "azure responses sends only the key on gpt-5.6", target: FormatOpenAIResponses, provider: provider.Azure, model: "gpt-5.6", want: &CanonicalCacheOptions{Key: "k"}},
		{name: "mistral sends only the key", target: FormatMistral, provider: provider.Mistral, model: "mistral-large-latest", want: &CanonicalCacheOptions{Key: "k"}},
		{name: "openrouter non-caching model gets nothing", target: FormatOpenRouter, provider: provider.OpenRouter, model: "meta-llama/llama-3.3-70b-instruct", want: nil},
		{name: "cerebras shares the openai format but gets nothing", target: FormatOpenAI, provider: provider.Cerebras, model: "gpt-oss-120b", want: nil},
		{name: "openai_compatible gets nothing", target: FormatOpenAI, provider: provider.OpenAICompatible, model: "gpt-5.6", want: nil},
		{name: "xai keys its cache by header", target: FormatXAI, provider: provider.XAI, model: "grok-4", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := cachedRequest(1, 2, CacheTTL1h)
			req.Model = tt.model
			req.CacheOptions = &CanonicalCacheOptions{Key: "k", Retention: "24h", Mode: "explicit", Options: json.RawMessage(`{"mode":"explicit","ttl":"30m"}`), Auto: bp("")}
			normalizeCacheIntent(req, tt.target, tt.provider, "")

			assert.Equal(t, tt.want, req.CacheOptions)
			assert.Nil(t, req.SystemCache)
			assert.Equal(t, []any{nil}, toolTTLs(req.Tools))
			assert.Equal(t, []any{nil, nil}, messageTTLs(req.Messages))
		})
	}
}

func TestNormalizeCacheIntent_ExplicitModeNeedsABreakpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		target   Format
		options  string
		messages int
		want     *CanonicalCacheOptions
	}{
		{name: "kept while a breakpoint is sent", target: FormatOpenAIResponses, options: `{"mode":"explicit"}`, messages: 1, want: &CanonicalCacheOptions{Mode: "explicit", Options: json.RawMessage(`{"mode":"explicit"}`)}},
		{name: "dropped with the options it was alone in", target: FormatOpenAI, options: `{"mode":"explicit"}`, messages: 1, want: nil},
		{name: "dropped when the request has no breakpoint", target: FormatOpenAIResponses, options: `{"mode":"explicit"}`, want: nil},
		{name: "other options stay", target: FormatOpenAI, options: `{"mode":"explicit","foo":1}`, messages: 1, want: &CanonicalCacheOptions{Options: json.RawMessage(`{"foo":1}`)}},
		{name: "implicit mode stays", target: FormatOpenAI, options: `{"mode":"implicit"}`, want: &CanonicalCacheOptions{Mode: "implicit", Options: json.RawMessage(`{"mode":"implicit"}`)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := &CanonicalRequest{Model: "gpt-5.6"}
			for range tt.messages {
				req.Messages = append(req.Messages, CanonicalMessage{Role: "user", Content: "m", Cache: bp("")})
			}
			req.CacheOptions = openAICacheOptions("", "", json.RawMessage(tt.options))
			normalizeCacheIntent(req, tt.target, provider.OpenAI, "")

			assert.Equal(t, tt.want, req.CacheOptions)
		})
	}
}

func TestNormalizeCacheIntent_ResponsesClearsAssistantBreakpointsBeforeTheCap(t *testing.T) {
	t.Parallel()

	req := &CanonicalRequest{
		Model:       "gpt-5.6",
		System:      "sys",
		SystemCache: bp(""),
		Messages: []CanonicalMessage{
			{Role: "user", Content: "u1", Cache: bp("")},
			{Role: "assistant", Content: "a1", Cache: bp("")},
			{Role: "user", Content: "u2", Cache: bp("")},
			{Role: "assistant", ToolCalls: []CanonicalToolCall{{ID: "c1", Name: "f"}}, Cache: bp("")},
			{Role: "tool", ToolCallID: "c1", Content: "out", Cache: bp("")},
		},
	}
	normalizeCacheIntent(req, FormatOpenAIResponses, provider.OpenAI, "")

	assert.NotNil(t, req.SystemCache)
	assert.Equal(t, []any{nil, nil, CacheTTL(""), nil, CacheTTL("")}, messageTTLs(req.Messages))
}

func TestNormalizeCacheIntent_ImageMarkers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		target Format
		want   []any
	}{
		{target: FormatAnthropic, want: []any{CacheTTL("")}},
		{target: FormatBedrock, want: []any{CacheTTL("")}},
		{target: FormatOpenAIResponses, want: []any{nil}},
	}
	for _, tt := range tests {
		t.Run(string(tt.target), func(t *testing.T) {
			t.Parallel()
			req := &CanonicalRequest{
				Model: "gpt-5.6",
				Messages: []CanonicalMessage{{
					Role:    "user",
					Content: "volatile",
					Images:  []CanonicalImage{{URL: "https://example.com/a.png"}},
					Cache:   &CanonicalCacheBreakpoint{image: 1, images: 1},
				}},
			}
			normalizeCacheIntent(req, tt.target, formatProvider(tt.target), "")

			assert.Equal(t, tt.want, messageTTLs(req.Messages))
		})
	}
}

func TestCacheTextJoin_ImageMarkerKeepsItsOwnTTL(t *testing.T) {
	t.Parallel()

	var text cacheTextJoin
	text.add("stable")
	text.markText(bp(CacheTTL1h), false)
	text.addImage()
	text.markImage(bp(CacheTTL5m), false)
	text.addImage()
	text.add("volatile")

	cache := text.breakpoint()
	at, ok := cachedImageIndex(cache, 2)
	assert.True(t, ok)
	assert.Equal(t, 0, at)
	assert.Equal(t, CacheTTL5m, cache.TTL)
	_, ok = cachedImageIndex(cache, 1)
	assert.False(t, ok, "a plugin that removed an image loses the marker")

	text.markText(bp(""), true)
	assert.False(t, text.breakpoint().onImage(), "a later text marker wins")
}

func TestCacheTextJoin_ImageMarkerKeepsTheTextMarkerBehindIt(t *testing.T) {
	t.Parallel()

	var text cacheTextJoin
	text.add("stable")
	text.markText(bp(CacheTTL1h), false)
	text.addImage()
	text.markImage(bp(CacheTTL5m), false)
	text.add("volatile")

	cache := text.breakpoint()
	require.True(t, cache.onImage())
	fallback := cache.withoutImages()
	require.NotNil(t, fallback)
	assert.False(t, fallback.onImage())
	assert.Equal(t, CacheTTL1h, fallback.TTL)
	parts, placed := cachedTextParts(text.String(), fallback)
	assert.True(t, placed)
	assert.Equal(t, []string{"stable", "volatile"}, parts)
}

func TestNormalizeCacheIntent_EffectiveModelPicksTheProfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, model, defaultModel string
		want                      []any
	}{
		{name: "default model", defaultModel: "gpt-5.6", want: []any{CacheTTL("")}},
		{name: "body model wins", model: "gpt-4o", defaultModel: "gpt-5.6", want: []any{nil}},
		{name: "no model", want: []any{nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := &CanonicalRequest{
				Model:    tt.model,
				Messages: []CanonicalMessage{{Role: "user", Content: "hi", Cache: bp("")}},
			}
			normalizeCacheIntent(req, FormatOpenAIResponses, provider.OpenAI, tt.defaultModel)

			assert.Equal(t, tt.want, messageTTLs(req.Messages))
			assert.Equal(t, tt.model, req.Model)
		})
	}
}

func TestNormalizeCacheIntent_ResponsesBreakpointsNeedGPT56(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		model      string
		mode       string
		wantSystem bool
		wantMsgs   []any
	}{
		{name: "implicit mode leaves one write to OpenAI", model: "gpt-5.6", wantSystem: true, wantMsgs: []any{nil, nil, CacheTTL(""), CacheTTL("")}},
		{name: "explicit mode uses all four writes", model: "openai/gpt-5.6", mode: "explicit", wantSystem: true, wantMsgs: []any{nil, CacheTTL(""), CacheTTL(""), CacheTTL("")}},
		{name: "older models get no breakpoint", model: "gpt-4o", wantMsgs: []any{nil, nil, nil, nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := cachedRequest(1, 4, "")
			req.Model = tt.model
			if tt.mode != "" {
				req.CacheOptions = &CanonicalCacheOptions{Mode: tt.mode, Options: json.RawMessage(`{"mode":"explicit"}`)}
			}
			normalizeCacheIntent(req, FormatOpenAIResponses, formatProvider(FormatOpenAIResponses), "")

			assert.Equal(t, tt.wantSystem, req.SystemCache != nil)
			assert.Equal(t, []any{nil}, toolTTLs(req.Tools))
			assert.Equal(t, tt.wantMsgs, messageTTLs(req.Messages))
		})
	}
}

func TestCacheTextJoin_ExtendKeepsTheMarkerOnItsBlock(t *testing.T) {
	t.Parallel()

	var system cacheTextJoin
	system.add("intro\nline")
	var msg cacheTextJoin
	msg.add("stable")
	msg.markText(bp(CacheTTL1h), false)
	msg.add("volatile")
	system.extend(&msg)

	cache := system.breakpoint()
	parts, placed := cachedTextParts(system.String(), cache)
	assert.True(t, placed)
	assert.Equal(t, []string{"intro\nline\nstable", "volatile"}, parts)
	assert.Equal(t, CacheTTL1h, cache.TTL)

	var empty, blank cacheTextJoin
	blank.add("")
	empty.extend(&blank)
	assert.Empty(t, empty.parts)
}

func TestNormalizeCacheIntent_OpenRouterBreakpointsFollowTheModel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		model     string
		breakable bool
		ttl       CacheTTL
		auto      bool
	}{
		{model: "anthropic/claude-sonnet-4.5", breakable: true, ttl: CacheTTL1h, auto: true},
		{model: "Anthropic/Claude-Opus-4", breakable: true, ttl: CacheTTL1h, auto: true},
		{model: "google/gemini-2.5-pro", breakable: true, ttl: CacheTTL5m},
		{model: "qwen/qwen3-max", breakable: true, ttl: CacheTTL5m},
		{model: "openai/gpt-5.6", breakable: true, ttl: CacheTTL5m},
		{model: "openai/gpt-4o"},
		{model: "google/gemma-3-27b-it"},
		{model: "openrouter/auto"},
		{model: ""},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			t.Parallel()
			req := cachedRequest(1, 1, CacheTTL1h)
			req.Model = tt.model
			req.CacheOptions = &CanonicalCacheOptions{Key: "k", Retention: "24h", Auto: bp(CacheTTL1h)}
			normalizeCacheIntent(req, FormatOpenRouter, provider.OpenRouter, "")

			assert.Equal(t, []any{nil}, toolTTLs(req.Tools), "OpenRouter takes no tool markers")
			if !tt.breakable {
				assert.Nil(t, req.SystemCache)
				assert.Equal(t, []any{nil}, messageTTLs(req.Messages))
				assert.Nil(t, req.CacheOptions)
				return
			}
			assert.Equal(t, tt.ttl, ttlOf(req.SystemCache))
			assert.Equal(t, []any{tt.ttl}, messageTTLs(req.Messages))
			if tt.auto {
				require.NotNil(t, req.CacheOptions)
				assert.Equal(t, &CanonicalCacheOptions{Auto: bp(CacheTTL1h)}, req.CacheOptions)
				return
			}
			assert.Nil(t, req.CacheOptions)
		})
	}
}

func TestAdaptRequest_AnthropicMarkersReachOpenRouterParts(t *testing.T) {
	t.Parallel()

	body := []byte(`{"model":"anthropic/claude-sonnet-4.5","max_tokens":64,"cache_control":{"type":"ephemeral"},` +
		`"system":[{"type":"text","text":"Long prefix.","cache_control":{"type":"ephemeral","ttl":"1h"}}],` +
		`"tools":[{"name":"t","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral"}}],` +
		`"messages":[{"role":"user","content":[{"type":"text","text":"Doc","cache_control":{"type":"ephemeral"}},{"type":"text","text":"Question?"}]}]}`)

	out, err := NewRegistry().AdaptRequestForProvider(body, FormatAnthropic, FormatOpenRouter, provider.OpenRouter, "")
	require.NoError(t, err)
	var got struct {
		CacheControl json.RawMessage `json:"cache_control"`
		Messages     []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Tools []map[string]json.RawMessage `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(out, &got))
	assert.JSONEq(t, `{"type":"ephemeral"}`, string(got.CacheControl))
	require.Len(t, got.Messages, 2)
	assert.JSONEq(t, `[{"type":"text","text":"Long prefix.","cache_control":{"type":"ephemeral","ttl":"1h"}}]`, string(got.Messages[0].Content))
	assert.JSONEq(t, `[{"type":"text","text":"Doc","cache_control":{"type":"ephemeral"}},{"type":"text","text":"Question?"}]`, string(got.Messages[1].Content))
	require.Len(t, got.Tools, 1)
	assert.NotContains(t, got.Tools[0], "cache_control")
	assert.NotContains(t, string(out), "prompt_cache")
}

func TestAdaptRequest_MistralCarriesTheCacheKey(t *testing.T) {
	t.Parallel()

	reg := NewRegistry()
	sources := map[Format]string{
		FormatOpenAI:          `{"model":"mistral-large-latest","prompt_cache_key":"tenant-42","prompt_cache_retention":"24h","messages":[{"role":"system","content":[{"type":"text","text":"s","cache_control":{"type":"ephemeral"}}]},{"role":"user","content":"hi"}]%s}`,
		FormatOpenAIResponses: `{"model":"mistral-large-latest","prompt_cache_key":"tenant-42","prompt_cache_retention":"24h","input":"hi"%s}`,
	}
	for source, tmpl := range sources {
		for _, stream := range []string{"", `,"stream":true`} {
			out, err := reg.AdaptRequestForProvider([]byte(fmt.Sprintf(tmpl, stream)), source, FormatMistral, provider.Mistral, "")
			require.NoError(t, err)
			var got map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(out, &got))
			assert.JSONEq(t, `"tenant-42"`, string(got["prompt_cache_key"]), "%s stream=%q", source, stream)
			assert.NotContains(t, got, "prompt_cache_retention")
			assert.NotContains(t, string(out), "cache_control")
		}
	}

	out, err := reg.AdaptRequestForProvider([]byte(`{"model":"mistral-large-latest","messages":[{"role":"user","content":"hi"}]}`), FormatOpenAI, FormatMistral, provider.Mistral, "")
	require.NoError(t, err)
	assert.NotContains(t, string(out), "prompt_cache")
}

func TestNormalizeCacheIntent_BedrockOrdersSystemMessagesWithSystem(t *testing.T) {
	t.Parallel()

	req := &CanonicalRequest{Messages: []CanonicalMessage{
		{Role: "user", Content: "u", Cache: bp(CacheTTL1h)},
		{Role: "system", Content: "s", Cache: bp(CacheTTL5m)},
		{Role: "assistant", Content: "a"},
		{Role: "user", Content: "u2"},
	}}
	normalizeCacheIntent(req, FormatBedrock, formatProvider(FormatBedrock), "")

	assert.Equal(t, []any{CacheTTL5m, CacheTTL5m, nil, nil}, messageTTLs(req.Messages))
}
