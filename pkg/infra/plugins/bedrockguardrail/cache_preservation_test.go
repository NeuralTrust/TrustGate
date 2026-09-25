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

package bedrockguardrail

import (
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewriteRequestAnonymizesOnlyTheMaskedMessage(t *testing.T) {
	t.Parallel()
	const email = "carol@example.com"
	cases := []struct {
		name   string
		format adapter.Format
		body   string
	}{
		{
			name:   "responses keeps prompt_cache_key and codex fields",
			format: adapter.FormatOpenAIResponses,
			body: `{"model":"gpt-5.6","instructions":"Stable instructions","input":[` +
				`{"type":"message","role":"user","content":[{"type":"input_text","text":"earlier turn"}]},` +
				`{"type":"message","role":"user","content":[{"type":"input_text","text":"my email is ` + email + `"}]}],` +
				`"prompt_cache_key":"tenant-42","prompt_cache_retention":"24h","store":false,"include":["reasoning.encrypted_content"],"reasoning":{"effort":"low"}}`,
		},
		{
			name:   "bedrock converse keeps cachePoints",
			format: adapter.FormatBedrock,
			body: `{"system":[{"text":"Stable"},{"cachePoint":{"type":"default"}}],"messages":[` +
				`{"role":"user","content":[{"text":"earlier"},{"cachePoint":{"type":"default"}}]},` +
				`{"role":"assistant","content":[{"text":"ok"}]},` +
				`{"role":"user","content":[{"text":"my email is ` + email + `"}]}],"inferenceConfig":{"maxTokens":32}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := adapter.NewRegistry()
			creq, err := reg.DecodeRequestFor([]byte(tc.body), tc.format)
			require.NoError(t, err)
			text, idx := lastUserText(creq)
			require.GreaterOrEqual(t, idx, 0)
			body, ok := rewriteRequest(reg, tc.format, []byte(tc.body), creq, idx, strings.ReplaceAll(text, email, "{EMAIL}"))
			require.True(t, ok)
			assert.Equal(t, strings.ReplaceAll(tc.body, email, "{EMAIL}"), string(body))
		})
	}
}

func TestRewriteRequestReencodesWhenAnUnmodelledCopyKeepsTheMaskedText(t *testing.T) {
	t.Parallel()
	const email = "carol@example.com"
	body := `{"messages":[{"role":"user","content":[{"text":"my email is ` + email + `"},{"guardContent":{"text":{"text":"` + email + `"}}}]}]}`
	reg := adapter.NewRegistry()
	creq, err := reg.DecodeRequestFor([]byte(body), adapter.FormatBedrock)
	require.NoError(t, err)
	text, idx := lastUserText(creq)
	require.GreaterOrEqual(t, idx, 0)
	out, ok := rewriteRequest(reg, adapter.FormatBedrock, []byte(body), creq, idx, strings.ReplaceAll(text, email, "{EMAIL}"))
	require.True(t, ok)
	assert.NotContains(t, string(out), email)
}
