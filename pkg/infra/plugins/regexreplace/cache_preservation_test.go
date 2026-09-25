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

func TestRequestRewriteChangesOnlyTheMaskedText(t *testing.T) {
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
			name:     "openai chat keeps unmodelled keys",
			provider: openAIProvider,
			body: `{"model":"gpt-4o","messages":[{"role":"system","content":"s"},{"role":"system","content":"t"},` +
				`{"role":"user","content":"to ` + cacheEmail + `"}],"n":2,"logprobs":true,"prompt_cache_key":"k"}`,
		},
		{
			name:     "codex responses body keeps reasoning, include and store",
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
			assert.Equal(t, strings.ReplaceAll(tc.body, cacheEmail, "[EMAIL]"), string(res.RequestBody))
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
