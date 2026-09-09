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

import "testing"

func TestBodyCarriesRetryableError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"empty", "", false},
		{"not json", "plain text", false},
		{"no error field", `{"choices":[]}`, false},
		{"anthropic overloaded", `{"error":{"type":"overloaded_error","message":"Overloaded"}}`, true},
		{"openai rate limit", `{"error":{"code":"rate_limit_exceeded","message":"slow down"}}`, true},
		{"insufficient quota", `{"error":{"type":"insufficient_quota"}}`, true},
		{"gemini unavailable", `{"error":{"status":"UNAVAILABLE","message":"service temporarily unavailable"}}`, true},
		{"terminal invalid request", `{"error":{"type":"invalid_request_error","message":"bad model"}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BodyCarriesRetryableError([]byte(tc.body)); got != tc.want {
				t.Errorf("BodyCarriesRetryableError(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestBodyCarriesModelNotFound(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"empty", "", false},
		{"not json", "plain text", false},
		{"no error field", `{"choices":[]}`, false},
		{
			"openai model not found",
			`{"error":{"message":"The model ` + "`gpt-9`" + ` does not exist or you do not have access to it.",` +
				`"type":"invalid_request_error","param":null,"code":"model_not_found"}}`,
			true,
		},
		{
			"vertex numeric code and not found status",
			`{"error":{"code":404,"message":"Publisher Model ` + "`gemini-9`" + ` was not found or your project ` +
				`does not have access to it.","status":"NOT_FOUND"}}`,
			true,
		},
		{
			"bedrock validation exception",
			`{"__type":"ValidationException","message":"The provided model identifier is invalid."}`,
			true,
		},
		{
			"anthropic not found",
			`{"type":"error","error":{"type":"not_found_error","message":"model: claude-99 not found"}}`,
			true,
		},
		{"rate limited", `{"error":{"code":"rate_limit_exceeded","message":"slow down"}}`, false},
		{
			"model exists but rejects the request",
			`{"error":{"type":"invalid_request_error","message":"model gpt-4.1 does not support tools"}}`,
			false,
		},
		{"overloaded", `{"error":{"type":"overloaded_error","message":"Overloaded"}}`, false},
		{
			"unrelated resource missing",
			`{"error":{"code":"not_found","message":"file file-123 not found"}}`,
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BodyCarriesModelNotFound([]byte(tc.body)); got != tc.want {
				t.Errorf("BodyCarriesModelNotFound(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestBodyRequiresReasoningEffortNone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "openai tool and reasoning conflict",
			body: `{"error":{"message":"Function tools with reasoning_effort are not supported for gpt-5.6-luna in /v1/chat/completions. To use function tools, use /v1/responses or set reasoning_effort to 'none'.","type":"invalid_request_error","param":"reasoning_effort"}}`,
			want: true,
		},
		{name: "ambiguous none", body: `{"error":{"message":"Function tools with reasoning_effort are not supported; none of these models supports them"}}`, want: false},
		{name: "different error type", body: `{"error":{"type":"server_error","message":"Function tools with reasoning_effort are not supported; set reasoning_effort to 'none'"}}`, want: false},
		{name: "different parameter", body: `{"error":{"type":"invalid_request_error","param":"tools","message":"Function tools with reasoning_effort are not supported; set reasoning_effort to 'none'"}}`, want: false},
		{name: "plain text is not trusted", body: "set reasoning_effort to none", want: false},
		{name: "unrelated invalid request", body: `{"error":{"message":"reasoning_effort is invalid"}}`, want: false},
		{name: "missing error envelope", body: `{"message":"Function tools with reasoning_effort are not supported; use none"}`, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BodyRequiresReasoningEffortNone([]byte(tc.body)); got != tc.want {
				t.Errorf("BodyRequiresReasoningEffortNone(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}
