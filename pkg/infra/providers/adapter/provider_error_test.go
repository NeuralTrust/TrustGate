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
