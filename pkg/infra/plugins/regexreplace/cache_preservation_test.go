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

package regexreplace

import (
	"context"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cacheEmail = "bob@example.com"

func TestRequestRewriteReencodesAndKeepsCacheMarkers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		provider string
		source   string
		body     string
	}{
		{
			name:     "anthropic system marker and ttl survive",
			provider: anthropicProvider,
			body: `{"model":"claude-sonnet-4-5","max_tokens":64,` +
				`"system":[{"type":"text","text":"Long stable prefix","cache_control":{"type":"ephemeral","ttl":"1h"}}],` +
				`"tools":[{"name":"lookup","input_schema":{"type":"object","properties":{"z":{},"a":{}}},"cache_control":{"type":"ephemeral","ttl":"1h"}}],` +
				`"messages":[{"role":"user","content":[{"type":"text","text":"history","cache_control":{"type":"ephemeral"}}]},` +
				`{"role":"assistant","content":"noted"},` +
				`{"role":"user","content":"write to ` + cacheEmail + `"}],"thinking":{"type":"enabled","budget_tokens":2048}}`,
		},
		{
			name:     "openai chat keeps the prompt cache key",
			provider: openAIProvider,
			body: `{"model":"gpt-4o","messages":[{"role":"system","content":"s"},{"role":"system","content":"t"},` +
				`{"role":"user","content":"to ` + cacheEmail + `"}],"n":2,"logprobs":true,"prompt_cache_key":"k"}`,
		},
		{
			name:     "codex responses body",
			provider: openAIProvider,
			source:   string(adapter.FormatOpenAIResponses),
			body: `{"model":"gpt-5.6","instructions":"You are Codex.","input":[` +
				`{"type":"message","role":"developer","content":[{"type":"input_text","text":"sandbox"}]},` +
				`{"type":"message","role":"user","content":[{"type":"input_text","text":"mail ` + cacheEmail + `"}]},` +
				`{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"gAAA"}],` +
				`"tools":[{"type":"function","name":"shell","strict":false,"parameters":{"type":"object"}}],` +
				`"tool_choice":"auto","parallel_tool_calls":false,"reasoning":{"effort":"high"},` +
				`"store":false,"include":["reasoning.encrypted_content"],"prompt_cache_key":"sess"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := New(adapter.NewRegistry(), nil)
			event, _ := newEvent()
			set := settings(targetRequest, maskRule(`bob@example\.com`, "[EMAIL]"))
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(tc.provider, tc.source, []byte(tc.body)), nil, event)
			res, err := p.Execute(context.Background(), in)
			require.NoError(t, err)

			format := adapter.Format(tc.provider)
			if tc.source != "" {
				format = adapter.Format(tc.source)
			}
			reg := adapter.NewRegistry()
			want, err := reg.DecodeRequestFor([]byte(strings.ReplaceAll(tc.body, cacheEmail, "[EMAIL]")), format)
			require.NoError(t, err)
			ad, err := reg.GetAdapter(format)
			require.NoError(t, err)
			encoded, err := ad.EncodeRequest(want)
			require.NoError(t, err)
			assert.Equal(t, string(encoded), string(res.RequestBody))
			assert.NotContains(t, string(res.RequestBody), cacheEmail)

			got, err := reg.DecodeRequestFor(res.RequestBody, format)
			require.NoError(t, err)
			assert.Equal(t, want.CacheOptions, got.CacheOptions)
			assert.Equal(t, want.SystemCache, got.SystemCache)
			require.Len(t, got.Messages, len(want.Messages))
			for i := range want.Messages {
				assert.Equal(t, want.Messages[i].Cache, got.Messages[i].Cache, "message %d", i)
			}
			require.Len(t, got.Tools, len(want.Tools))
			for i := range want.Tools {
				assert.Equal(t, want.Tools[i].Cache, got.Tools[i].Cache, "tool %d", i)
			}
		})
	}
}

func TestRequestRewriteNoMatchForwardsTheBodyUnchanged(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	event, _ := newEvent()
	body := []byte(`{"model":"claude","max_tokens":8,"system":[{"type":"text","text":"s","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hi"}]}`)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(targetRequest, maskRule("nomatch", "x")), reqCtx(anthropicProvider, "", body), nil, event)
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	assert.Nil(t, res.RequestBody)
}

func TestRequestRewriteReencodesWhenAnUnmodelledCopyKeepsTheMaskedText(t *testing.T) {
	t.Parallel()
	body := `{"model":"gpt-5","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"notify ` + cacheEmail + `"}]},` +
		`{"type":"reasoning","summary":[{"type":"summary_text","text":"notify ` + cacheEmail + `"}],"encrypted_content":"gAAA"}],"store":false}`
	p := New(adapter.NewRegistry(), nil)
	event, _ := newEvent()
	set := settings(targetRequest, maskRule(`bob@example\.com`, "[EMAIL]"))
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIProvider, string(adapter.FormatOpenAIResponses), []byte(body)), nil, event)
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	assert.NotContains(t, string(res.RequestBody), cacheEmail)
	assert.NotContains(t, string(res.RequestBody), "summary_text")
}
