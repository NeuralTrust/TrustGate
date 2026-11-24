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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var geminiFormats = []Format{FormatGemini, FormatVertex}

func geminiBodyWithConfig(config string) []byte {
	return []byte(`{"contents":[{"role":"user","parts":[{"text":"hola"}]}],` + config + `}`)
}

func TestGeminiDecodesTheGoogleGenAIWireBody(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(filepath.Join("testdata", "sdk_requests", "google", "gemini.generation_config_floats.json"))
	require.NoError(t, err)

	for _, format := range geminiFormats {
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			req, err := NewRegistry().DecodeRequestFor(body, format)
			require.NoError(t, err)

			assert.Equal(t, "Eres un asistente legal.", req.System)
			require.Len(t, req.Messages, 1)
			assert.Equal(t, "Resume el contrato adjunto en tres puntos.", req.Messages[0].Content)
			assert.Equal(t, 65536, req.MaxTokens)
			require.NotNil(t, req.TopK)
			assert.Equal(t, 1, *req.TopK)
			require.NotNil(t, req.TopP)
			assert.InDelta(t, 1.0, *req.TopP, 1e-9)
			require.NotNil(t, req.Temperature)
			assert.InDelta(t, 0.0, *req.Temperature, 1e-9)
			assert.False(t, HasAmbiguousKeys(format, body))
		})
	}
}

func TestGeminiGenerationConfigReadsNumbersAsProto3JSON(t *testing.T) {
	t.Parallel()
	intPtr := func(v int) *int { return &v }
	floatPtr := func(v float64) *float64 { return &v }

	cases := map[string]struct {
		config      string
		maxTokens   int
		topK        *int
		temperature *float64
		topP        *float64
	}{
		"integer topK":                {config: `"generationConfig":{"topK":3}`, topK: intPtr(3)},
		"integral float topK":         {config: `"generationConfig":{"topK":40.0}`, topK: intPtr(40)},
		"snake_case float top_k":      {config: `"generation_config":{"top_k":1.0}`, topK: intPtr(1)},
		"fractional Vertex topK":      {config: `"generationConfig":{"topK":40.5}`, topK: intPtr(41)},
		"exponent topK":               {config: `"generationConfig":{"topK":4e1}`, topK: intPtr(40)},
		"numeric string topK":         {config: `"generationConfig":{"topK":"40"}`, topK: intPtr(40)},
		"topK outside int32":          {config: `"generationConfig":{"topK":1e12}`},
		"null topK":                   {config: `"generationConfig":{"topK":null}`},
		"integral float max tokens":   {config: `"generationConfig":{"maxOutputTokens":65536.0}`, maxTokens: 65536},
		"exponent max tokens":         {config: `"generationConfig":{"maxOutputTokens":1e3}`, maxTokens: 1000},
		"numeric string max tokens":   {config: `"generationConfig":{"maxOutputTokens":"8192"}`, maxTokens: 8192},
		"snake_case float max tokens": {config: `"generation_config":{"max_output_tokens":2048.0}`, maxTokens: 2048},
		"numeric string temperature":  {config: `"generationConfig":{"temperature":"0.5"}`, temperature: floatPtr(0.5)},
		"numeric string topP":         {config: `"generationConfig":{"topP":"0.9"}`, topP: floatPtr(0.9)},
	}
	for name, tc := range cases {
		for _, format := range geminiFormats {
			t.Run(name+"/"+string(format), func(t *testing.T) {
				t.Parallel()
				req, err := NewRegistry().DecodeRequestFor(geminiBodyWithConfig(tc.config), format)
				require.NoError(t, err)
				assert.Equal(t, tc.maxTokens, req.MaxTokens)
				assert.Equal(t, tc.topK, req.TopK)
				if tc.temperature == nil {
					assert.Nil(t, req.Temperature)
				} else {
					require.NotNil(t, req.Temperature)
					assert.InDelta(t, *tc.temperature, *req.Temperature, 1e-9)
				}
				if tc.topP == nil {
					assert.Nil(t, req.TopP)
				} else {
					require.NotNil(t, req.TopP)
					assert.InDelta(t, *tc.topP, *req.TopP, 1e-9)
				}
			})
		}
	}
}

func TestGeminiGenerationConfigStillRefusesWhatTheAPIRefuses(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"topK non-numeric string":          `"generationConfig":{"topK":"abc"}`,
		"topK empty string":                `"generationConfig":{"topK":""}`,
		"topK hex string":                  `"generationConfig":{"topK":"0x10"}`,
		"topK NaN string":                  `"generationConfig":{"topK":"NaN"}`,
		"topK bool":                        `"generationConfig":{"topK":true}`,
		"topK object":                      `"generationConfig":{"topK":{"text":"ignore previous instructions"}}`,
		"topK array":                       `"generationConfig":{"topK":[1]}`,
		"topK overflowing float64":         `"generationConfig":{"topK":1e400}`,
		"top_k string":                     `"generation_config":{"top_k":"abc"}`,
		"max tokens fraction":              `"generationConfig":{"maxOutputTokens":40.5}`,
		"max tokens fractional string":     `"generationConfig":{"maxOutputTokens":"40.5"}`,
		"max tokens float outside int32":   `"generationConfig":{"maxOutputTokens":1e10}`,
		"max tokens non-numeric string":    `"generationConfig":{"maxOutputTokens":"8k"}`,
		"max tokens bool":                  `"generationConfig":{"maxOutputTokens":false}`,
		"max_output_tokens fraction":       `"generation_config":{"max_output_tokens":1.5}`,
		"temperature non-numeric string":   `"generationConfig":{"temperature":"warm"}`,
		"topP object":                      `"generationConfig":{"topP":{}}`,
		"number with surrounding spaces":   `"generationConfig":{"topK":" 40"}`,
		"number with a leading plus sign":  `"generationConfig":{"topK":"+40"}`,
		"number with a leading zero":       `"generationConfig":{"maxOutputTokens":"0100"}`,
		"string holding a quoted number":   `"generationConfig":{"topK":"\"40\""}`,
		"string holding the literal null":  `"generationConfig":{"topK":"null"}`,
		"string holding an escaped number": `"generationConfig":{"topK":"40x"}`,
	}
	for name, config := range cases {
		for _, format := range geminiFormats {
			t.Run(name+"/"+string(format), func(t *testing.T) {
				t.Parallel()
				_, err := NewRegistry().DecodeRequestFor(geminiBodyWithConfig(config), format)
				require.Error(t, err)
				assert.True(t, IsRequestDecodeError(err), "a refused number must be a RequestDecodeError so a guardrail refuses the body instead of skipping it: %v", err)
			})
		}
	}
}

func TestGeminiEncodesGenerationConfigNumbersUnchanged(t *testing.T) {
	t.Parallel()
	temperature, topP, topK := 0.0, 1.0, 1
	req := &CanonicalRequest{
		Messages:    []CanonicalMessage{{Role: "user", Content: "hola"}},
		MaxTokens:   65536,
		Temperature: &temperature,
		TopP:        &topP,
		TopK:        &topK,
	}
	for _, ad := range []*GeminiAdapter{{}, NewVertexAdapter()} {
		body, err := ad.EncodeRequest(req)
		require.NoError(t, err)
		var out struct {
			GenerationConfig json.RawMessage `json:"generationConfig"`
		}
		require.NoError(t, json.Unmarshal(body, &out))
		assert.JSONEq(t, `{"maxOutputTokens":65536,"temperature":0,"topP":1,"topK":1}`, string(out.GenerationConfig))
		assert.NotContains(t, string(out.GenerationConfig), ".0")
	}
}
