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
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewriteRequestReencodesAndKeepsCacheMarkers(t *testing.T) {
	t.Parallel()
	body := `{"model":"claude-sonnet-4-5","max_tokens":64,` +
		`"system":[{"type":"text","text":"Stable prefix\nsecond line","cache_control":{"type":"ephemeral","ttl":"1h"}}],` +
		`"messages":[{"role":"user","content":[{"type":"text","text":"history","cache_control":{"type":"ephemeral"}}]},` +
		`{"role":"assistant","content":"ok"},{"role":"user","content":"card 4111 1111 1111 1111"}],` +
		`"tools":[{"name":"t","input_schema":{"type":"object","properties":{"b":{},"a":{}}}}],"thinking":{"type":"enabled","budget_tokens":2048}}`
	reg := adapter.NewRegistry()
	creq, err := reg.DecodeRequestFor([]byte(body), adapter.FormatAnthropic)
	require.NoError(t, err)
	masked := strings.ReplaceAll(joinRequestText(creq), "4111 1111 1111 1111", "[CARD]")

	out, ok := rewriteRequest(reg, adapter.FormatAnthropic, []byte(body), creq, masked)

	require.True(t, ok)
	ad, err := reg.GetAdapter(adapter.FormatAnthropic)
	require.NoError(t, err)
	want, err := ad.EncodeRequest(creq)
	require.NoError(t, err)
	assert.Equal(t, string(want), string(out))
	assert.NotContains(t, string(out), "4111")
	decoded, err := reg.DecodeRequestFor(out, adapter.FormatAnthropic)
	require.NoError(t, err)
	require.NotNil(t, decoded.SystemCache)
	assert.Equal(t, adapter.CacheTTL1h, decoded.SystemCache.TTL)
	require.NotNil(t, decoded.Messages[0].Cache)
	assert.Equal(t, "card [CARD]", decoded.Messages[2].Content)
}

func TestRewriteRequestForwardsAnUnchangedMaskAsItCame(t *testing.T) {
	t.Parallel()
	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"hello"}],"container":"c"}`
	reg := adapter.NewRegistry()
	creq, err := reg.DecodeRequestFor([]byte(body), adapter.FormatAnthropic)
	require.NoError(t, err)

	out, ok := rewriteRequest(reg, adapter.FormatAnthropic, []byte(body), creq, joinRequestText(creq))

	require.True(t, ok)
	assert.Equal(t, body, string(out))
}

func TestRewriteResponseKeepsCacheUsage(t *testing.T) {
	t.Parallel()
	body := `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"card 4111"}],` +
		`"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":900,"cache_creation_input_tokens":100,` +
		`"cache_creation":{"ephemeral_5m_input_tokens":40,"ephemeral_1h_input_tokens":60}}}`
	reg := adapter.NewRegistry()
	before, err := reg.DecodeResponseFor([]byte(body), adapter.FormatAnthropic)
	require.NoError(t, err)
	cresp, err := reg.DecodeResponseFor([]byte(body), adapter.FormatAnthropic)
	require.NoError(t, err)

	out, ok := rewriteResponse(reg, adapter.FormatAnthropic, cresp, "card [CARD]")

	require.True(t, ok)
	after, err := reg.DecodeResponseFor(out, adapter.FormatAnthropic)
	require.NoError(t, err)
	assert.Equal(t, "card [CARD]", after.Content)
	require.NotNil(t, after.Usage)
	assert.Equal(t, 900, after.Usage.CachedInputTokens)
	assert.Equal(t, 100, after.Usage.CacheWriteInputTokens)
	assert.Equal(t, 60, after.Usage.CacheWrite1hInputTokens)
	assert.Equal(t, before.Usage.InputTokens, after.Usage.InputTokens)
}

func TestRewriteRequestReencodesWhenAnUnmodelledCopyKeepsTheMaskedText(t *testing.T) {
	t.Parallel()
	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"card 4111 1111 1111 1111"},` +
		`{"role":"assistant","content":[{"type":"thinking","thinking":"the card is 4111 1111 1111 1111","signature":"s"},{"type":"text","text":"ok"}]},` +
		`{"role":"user","content":"go"}]}`
	reg := adapter.NewRegistry()
	creq, err := reg.DecodeRequestFor([]byte(body), adapter.FormatAnthropic)
	require.NoError(t, err)
	masked := strings.ReplaceAll(joinRequestText(creq), "4111 1111 1111 1111", "[CARD]")

	out, ok := rewriteRequest(reg, adapter.FormatAnthropic, []byte(body), creq, masked)

	require.True(t, ok)
	assert.NotContains(t, string(out), "4111")
	assert.NotContains(t, string(out), `"thinking"`)
}

func TestRewriteRequestKeepsResponsesStorageKeys(t *testing.T) {
	t.Parallel()
	body := `{"model":"gpt-5","store":false,"previous_response_id":"resp_1","include":["reasoning.encrypted_content"],` +
		`"reasoning":{"effort":"low"},"metadata":{"who":"bob@corp.example"},"input":"mail bob@corp.example"}`
	reg := adapter.NewRegistry()
	creq, err := reg.DecodeRequestFor([]byte(body), adapter.FormatOpenAIResponses)
	require.NoError(t, err)
	masked := strings.ReplaceAll(joinRequestText(creq), "bob@corp.example", "[EMAIL]")

	out, ok := rewriteRequest(reg, adapter.FormatOpenAIResponses, []byte(body), creq, masked)

	require.True(t, ok)
	assert.NotContains(t, string(out), "bob@corp.example")
	for _, kept := range []string{`"store":false`, `"previous_response_id":"resp_1"`, `"include":["reasoning.encrypted_content"]`, `"reasoning":{"effort":"low"}`} {
		assert.Contains(t, string(out), kept)
	}
}
