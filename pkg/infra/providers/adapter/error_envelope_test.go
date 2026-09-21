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
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdaptErrorBody(t *testing.T) {
	t.Parallel()
	openai := []byte(`{"error":{"message":"bad","type":"invalid_request_error","param":"max_tokens"}}`)
	tests := []struct {
		name   string
		status int
		source Format
		body   []byte
		want   string
	}{
		{name: "openai passthrough", status: 400, source: FormatOpenAI, body: openai, want: string(openai)},
		{name: "anthropic 400", status: 400, source: FormatAnthropic, body: openai, want: `{"type":"error","error":{"type":"invalid_request_error","message":"bad"}}`},
		{name: "anthropic 401", status: 401, source: FormatAnthropic, body: openai, want: `{"type":"error","error":{"type":"authentication_error","message":"bad"}}`},
		{name: "anthropic 429", status: 429, source: FormatAnthropic, body: openai, want: `{"type":"error","error":{"type":"rate_limit_error","message":"bad"}}`},
		{name: "gemini 400", status: 400, source: FormatGemini, body: openai, want: `{"error":{"code":400,"message":"bad","status":"INVALID_ARGUMENT"}}`},
		{name: "cohere", status: 400, source: FormatCohere, body: openai, want: `{"message":"bad"}`},
		{name: "empty body uses status text", status: 400, source: FormatAnthropic, body: nil, want: `{"type":"error","error":{"type":"invalid_request_error","message":"Bad Request"}}`},
		{name: "bedrock type extracted", status: 400, source: FormatAnthropic, body: []byte(`{"__type":"ValidationException","message":"nope"}`), want: `{"type":"error","error":{"type":"invalid_request_error","message":"nope"}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AdaptErrorBody(tc.body, tc.status, tc.source)
			assert.JSONEq(t, tc.want, string(got))
		})
	}
}

func TestEncodeErrorBody_AnthropicTypes(t *testing.T) {
	t.Parallel()
	raw := EncodeErrorBody(FormatAnthropic, http.StatusNotFound, "missing")
	var env map[string]any
	require.NoError(t, json.Unmarshal(raw, &env))
	errObj := env["error"].(map[string]any)
	assert.Equal(t, "not_found_error", errObj["type"])
}

func TestStreamErrorEvent_UpstreamTerminatedGolden(t *testing.T) {
	t.Parallel()
	const (
		openaiGolden    = `data: {"error":{"message":"upstream stream terminated unexpectedly","type":"upstream_error"}}`
		anthropicGolden = "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"upstream stream terminated unexpectedly\"}}\n"
		geminiGolden    = "data: {\"error\":{\"code\":500,\"message\":\"upstream stream terminated unexpectedly\",\"status\":\"INTERNAL\"}}\n"
	)
	tests := []struct {
		name   string
		source Format
		want   string
	}{
		{name: "openai", source: FormatOpenAI, want: openaiGolden},
		{name: "azure", source: FormatAzure, want: openaiGolden},
		{name: "groq", source: FormatGroq, want: openaiGolden},
		{name: "deepseek", source: FormatDeepSeek, want: openaiGolden},
		{name: "xai", source: FormatXAI, want: openaiGolden},
		{name: "openrouter", source: FormatOpenRouter, want: openaiGolden},
		{name: "mistral", source: FormatMistral, want: openaiGolden},
		{name: "cohere falls through to openai", source: FormatCohere, want: openaiGolden},
		{name: "responses falls through to openai", source: FormatOpenAIResponses, want: openaiGolden},
		{name: "unknown falls through to openai", source: Format("something-else"), want: openaiGolden},
		{name: "anthropic", source: FormatAnthropic, want: anthropicGolden},
		{name: "gemini", source: FormatGemini, want: geminiGolden},
		{name: "vertex", source: FormatVertex, want: geminiGolden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := StreamErrorEvent(
				tc.source,
				http.StatusInternalServerError,
				StreamErrorTypeUpstream,
				StreamErrorMessageUpstreamTerminated,
			)
			assert.Equal(t, tc.want, string(got))
			assert.Equal(t, tc.want, string(StreamErrorEvent(tc.source, 0, "", "")))
		})
	}
}

func TestStreamErrorEvent_HonoursArguments(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		source  Format
		status  int
		errType string
		message string
		want    string
	}{
		{
			name:    "openai carries type and message",
			source:  FormatOpenAI,
			status:  http.StatusForbidden,
			errType: "content_filter",
			message: "blocked",
			want:    `data: {"error":{"message":"blocked","type":"content_filter"}}`,
		},
		{
			name:    "gemini carries status",
			source:  FormatGemini,
			status:  http.StatusForbidden,
			errType: "content_filter",
			message: "blocked",
			want:    "data: {\"error\":{\"code\":403,\"message\":\"blocked\",\"status\":\"PERMISSION_DENIED\"}}\n",
		},
		{
			name:    "anthropic carries status",
			source:  FormatAnthropic,
			status:  http.StatusForbidden,
			errType: "content_filter",
			message: "blocked",
			want:    "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"permission_error\",\"message\":\"blocked\"}}\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := StreamErrorEvent(tc.source, tc.status, tc.errType, tc.message)
			assert.Equal(t, tc.want, string(got))
		})
	}
}

func TestStreamBlockedEvent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		source Format
		want   []string
	}{
		{
			name:   "openai",
			source: FormatOpenAI,
			want: []string{
				`data: {"error":{"message":"blocked","type":"content_filter"}}`,
				"",
			},
		},
		{
			name:   "azure normalizes to openai",
			source: FormatAzure,
			want: []string{
				`data: {"error":{"message":"blocked","type":"content_filter"}}`,
				"",
			},
		},
		{
			name:   "anthropic",
			source: FormatAnthropic,
			want: []string{
				"event: error",
				`data: {"type":"error","error":{"type":"permission_error","message":"blocked"}}`,
				"",
			},
		},
		{
			name:   "gemini",
			source: FormatGemini,
			want: []string{
				`data: {"error":{"code":403,"message":"blocked","status":"PERMISSION_DENIED"}}`,
				"",
			},
		},
		{
			name:   "cohere falls through to openai: its union has no error member",
			source: FormatCohere,
			want: []string{
				`data: {"error":{"message":"blocked","type":"content_filter"}}`,
				"",
			},
		},
		{
			name:   "responses",
			source: FormatOpenAIResponses,
			want: []string{
				"event: error",
				`data: {"type":"error","code":"content_filter","message":"blocked","param":null}`,
				"",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := StreamBlockedEvent(tc.source, "content_filter", "blocked")
			lines := make([]string, 0, len(got))
			for _, line := range got {
				lines = append(lines, string(line))
			}
			assert.Equal(t, tc.want, lines)
		})
	}
}

func TestStreamBlockedEvent_FramingIsUniform(t *testing.T) {
	t.Parallel()
	sources := []Format{
		FormatOpenAI, FormatAzure, FormatGroq, FormatAnthropic, FormatGemini,
		FormatVertex, FormatCohere, FormatOpenAIResponses, Format("something-else"),
	}
	for _, source := range sources {
		t.Run(string(source), func(t *testing.T) {
			t.Parallel()
			got := StreamBlockedEvent(source, "", "")
			require.NotEmpty(t, got)
			assert.Empty(t, got[len(got)-1])
			for _, line := range got {
				assert.NotContains(t, string(line), "\n")
			}
			data := got[len(got)-2]
			assert.Contains(t, string(data), "response blocked by content filter")
			var decoded map[string]any
			require.NoError(t, json.Unmarshal(bytes.TrimPrefix(data, []byte("data: ")), &decoded))
		})
	}
}
