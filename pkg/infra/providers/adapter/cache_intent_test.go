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
			normalizeCacheIntent(tt.req, FormatAnthropic)
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
	normalizeCacheIntent(req, FormatAnthropic)

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
			normalizeCacheIntent(req, tt.target)
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
			normalizeCacheIntent(req, target)

			assert.Nil(t, req.SystemCache)
			assert.Nil(t, req.CacheOptions)
			assert.Equal(t, []any{nil}, toolTTLs(req.Tools))
			assert.Equal(t, []any{nil, nil}, messageTTLs(req.Messages))
		})
	}
}

func TestNormalizeCacheIntent_BedrockDropsAutoAndRequestOptions(t *testing.T) {
	t.Parallel()

	req := cachedRequest(0, 1, CacheTTL1h)
	req.CacheOptions = &CanonicalCacheOptions{Key: "k", Auto: bp("")}
	normalizeCacheIntent(req, FormatBedrock)

	assert.Nil(t, req.CacheOptions)
	assert.Equal(t, CacheTTL1h, req.SystemCache.TTL)
	assert.Equal(t, []any{CacheTTL1h}, messageTTLs(req.Messages))
}

func TestNormalizeCacheIntent_NoIntentIsANoOp(t *testing.T) {
	t.Parallel()

	normalizeCacheIntent(nil, FormatAnthropic)
	req := &CanonicalRequest{System: "s", Messages: []CanonicalMessage{{Role: "user", Content: "hi"}}, Tools: []CanonicalTool{{Name: "t"}}}
	want := *req
	normalizeCacheIntent(req, FormatAnthropic)
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
	normalizeCacheIntent(req, FormatAnthropic)

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
	normalizeCacheIntent(req, FormatAnthropic)
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
		"gpt-5.6":               true,
		"gpt-5.6-mini":          true,
		"gpt-5.6-2026-08-01":    true,
		"openai/gpt-5.7":        true,
		"GPT-5.10":              true,
		"gpt-6":                 true,
		"gpt-6.1-codex":         true,
		"gpt-5.5":               false,
		"gpt-5":                 false,
		"gpt-5-mini":            false,
		"gpt-5.1-codex":         false,
		"gpt-4o":                false,
		"gpt-4.1":               false,
		"gpt-oss-120b":          false,
		"o3":                    false,
		"claude-sonnet-4-5":     false,
		"":                      false,
		"openai/gpt-5.5-turbo":  false,
		"my-gpt-5.6-deployment": false,
		"gpt-35-turbo":          false,
		"gpt-50":                false,
	}
	for model, want := range tests {
		t.Run(model, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, want, isGPT56OrLater(model))
		})
	}
}

func TestNormalizeCacheIntent_OpenAIChatTargetsKeepOnlyRequestKeys(t *testing.T) {
	t.Parallel()

	options := json.RawMessage(`{"mode":"explicit","ttl":"30m"}`)
	tests := []struct {
		name   string
		target Format
		model  string
		want   *CanonicalCacheOptions
	}{
		{name: "openai before gpt-5.6 keeps retention", target: FormatOpenAI, model: "gpt-4o", want: &CanonicalCacheOptions{Key: "k", Retention: "24h"}},
		{name: "openai gpt-5.6 keeps options", target: FormatOpenAI, model: "gpt-5.6", want: &CanonicalCacheOptions{Key: "k", Mode: "explicit", Options: options}},
		{name: "azure follows the model", target: FormatAzure, model: "gpt-4.1", want: &CanonicalCacheOptions{Key: "k", Retention: "24h"}},
		{name: "responses before gpt-5.6", target: FormatOpenAIResponses, model: "gpt-4o", want: &CanonicalCacheOptions{Key: "k", Retention: "24h"}},
		{name: "xai keys its cache by header", target: FormatXAI, model: "grok-4", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := cachedRequest(1, 2, CacheTTL1h)
			req.Model = tt.model
			req.CacheOptions = &CanonicalCacheOptions{Key: "k", Retention: "24h", Mode: "explicit", Options: options, Auto: bp("")}
			normalizeCacheIntent(req, tt.target)

			assert.Equal(t, tt.want, req.CacheOptions)
			assert.Nil(t, req.SystemCache)
			assert.Equal(t, []any{nil}, toolTTLs(req.Tools))
			assert.Equal(t, []any{nil, nil}, messageTTLs(req.Messages))
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
			normalizeCacheIntent(req, FormatOpenAIResponses)

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
