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

	for _, target := range []Format{FormatGemini, FormatVertex, FormatGroq, FormatCohere, FormatDeepSeek, FormatOpenAI, FormatOpenAIResponses} {
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
