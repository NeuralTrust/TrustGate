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
