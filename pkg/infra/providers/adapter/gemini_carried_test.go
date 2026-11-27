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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const geminiBodyWithUnmodelledConfig = `{"contents":[{"role":"user","parts":[{"text":"my email is ana@corp.example"}]}],` +
	`"safetySettings":[{"category":"HARM_CATEGORY_HATE_SPEECH","threshold":"BLOCK_NONE"}],` +
	`"cachedContent":"cachedContents/abc",` +
	`"labels":{"owner":"ana@corp.example"},` +
	`"toolConfig":{"functionCallingConfig":{"mode":"ANY"}},` +
	`"generationConfig":{"temperature":0.2,"stopSequences":["END"],"seed":7,"thinkingConfig":{"thinkingBudget":0},` +
	`"responseMimeType":"text/x.enum","responseSchema":{"type":"STRING","enum":["yes","no"]},` +
	`"speechConfig":{"multiSpeakerVoiceConfig":{"speakerVoiceConfigs":[{"speaker":"Ana"}]}}}}`

func geminiFields(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &fields))
	return fields
}

func maskedGeminiReencode(t *testing.T, ad *GeminiAdapter, body string) []byte {
	t.Helper()
	req, err := ad.DecodeRequest([]byte(body))
	require.NoError(t, err)
	require.NotEmpty(t, req.Messages)
	req.Messages[0].Content = strings.ReplaceAll(req.Messages[0].Content, "ana@corp.example", "[EMAIL]")
	out, err := ad.EncodeRequest(req)
	require.NoError(t, err)
	return out
}

func TestGeminiReencodeKeepsConfigWithoutPromptText(t *testing.T) {
	t.Parallel()
	for name, ad := range map[string]*GeminiAdapter{"gemini": {}, "vertex": NewVertexAdapter()} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := maskedGeminiReencode(t, ad, geminiBodyWithUnmodelledConfig)
			fields := geminiFields(t, out)

			assert.NotContains(t, string(out), "ana@corp.example")
			assert.JSONEq(t, `[{"category":"HARM_CATEGORY_HATE_SPEECH","threshold":"BLOCK_NONE"}]`, string(fields["safetySettings"]))
			assert.JSONEq(t, `"cachedContents/abc"`, string(fields["cachedContent"]))
			assert.JSONEq(t, `{"temperature":0.2,"stopSequences":["END"],"seed":7,"thinkingConfig":{"thinkingBudget":0},`+
				`"responseMimeType":"text/x.enum","responseSchema":{"type":"STRING","enum":["yes","no"]}}`, string(fields["generationConfig"]))
			for _, dropped := range []string{"labels", "toolConfig"} {
				assert.NotContains(t, fields, dropped)
			}
			assert.NotContains(t, string(out), "speechConfig")

			again, err := ad.DecodeRequest(out)
			require.NoError(t, err)
			assert.Equal(t, "my email is [EMAIL]", again.Messages[0].Content)
			assert.False(t, HasAmbiguousKeys(FormatGemini, out))
		})
	}
}

func TestGeminiReencodeWritesSnakeCaseCarriedKeysInCamelCase(t *testing.T) {
	t.Parallel()
	body := `{"contents":[{"parts":[{"text":"hola"}]}],"safety_settings":[{"category":"C","threshold":"BLOCK_NONE"}],` +
		`"cached_content":"cachedContents/x","generation_config":{"thinking_config":{"thinking_budget":0},"stop_sequences":["a"],"stopSequences":["b"]}}`
	ad := &GeminiAdapter{}
	req, err := ad.DecodeRequest([]byte(body))
	require.NoError(t, err)
	out, err := ad.EncodeRequest(req)
	require.NoError(t, err)

	fields := geminiFields(t, out)
	assert.JSONEq(t, `[{"category":"C","threshold":"BLOCK_NONE"}]`, string(fields["safetySettings"]))
	assert.JSONEq(t, `"cachedContents/x"`, string(fields["cachedContent"]))
	assert.JSONEq(t, `{"thinkingConfig":{"thinking_budget":0},"stopSequences":["b"]}`, string(fields["generationConfig"]))
	assert.NotContains(t, string(out), "safety_settings")
	assert.NotContains(t, string(out), "stop_sequences")
}

func TestGeminiReencodeLeavesOutNullCarriedKeys(t *testing.T) {
	t.Parallel()
	body := `{"contents":[{"parts":[{"text":"hola"}]}],"safetySettings":null,"cachedContent":"","generationConfig":{"thinkingConfig":null}}`
	ad := &GeminiAdapter{}
	req, err := ad.DecodeRequest([]byte(body))
	require.NoError(t, err)
	assert.Empty(t, req.RequestExtensions)
	out, err := ad.EncodeRequest(req)
	require.NoError(t, err)
	assert.JSONEq(t, `{"contents":[{"role":"user","parts":[{"text":"hola"}]}]}`, string(out))
}

func TestGeminiReencodeKeepsOneResponseMimeType(t *testing.T) {
	t.Parallel()
	body := `{"contents":[{"parts":[{"text":"hola"}]}],"generationConfig":{"responseMimeType":"application/json","responseSchema":{"type":"OBJECT"}}}`
	ad := &GeminiAdapter{}
	req, err := ad.DecodeRequest([]byte(body))
	require.NoError(t, err)
	out, err := ad.EncodeRequest(req)
	require.NoError(t, err)

	assert.Equal(t, 1, strings.Count(string(out), "responseMimeType"))
	assert.JSONEq(t, `{"responseMimeType":"application/json","responseSchema":{"type":"OBJECT"}}`, string(geminiFields(t, out)["generationConfig"]))
}

func TestGeminiEncodeReadsOnlyItsOwnCarriedKeys(t *testing.T) {
	t.Parallel()
	req := &CanonicalRequest{
		Messages: []CanonicalMessage{{Role: "user", Content: "hola"}},
		RequestExtensions: map[string]json.RawMessage{
			"store":            json.RawMessage(`false`),
			"reasoning":        json.RawMessage(`{"effort":"low"}`),
			"labels":           json.RawMessage(`{"owner":"ana@corp.example"}`),
			"generationConfig": json.RawMessage(`{"speechConfig":{"voiceConfig":{}},"seed":3}`),
		},
	}
	out, err := (&GeminiAdapter{}).EncodeRequest(req)
	require.NoError(t, err)
	assert.JSONEq(t, `{"contents":[{"role":"user","parts":[{"text":"hola"}]}],"generationConfig":{"seed":3}}`, string(out))
}

func TestGeminiCarriedKeysStayOutOfCrossFormatTranslation(t *testing.T) {
	t.Parallel()
	out, err := NewRegistry().AdaptRequest([]byte(geminiBodyWithUnmodelledConfig), FormatGemini, FormatOpenAI)
	require.NoError(t, err)
	for _, key := range []string{"safetySettings", "cachedContent", "thinkingConfig", "stopSequences", "responseSchema"} {
		assert.NotContains(t, string(out), key)
	}
}
