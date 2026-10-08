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

func TestBedrockErrorType(t *testing.T) {
	t.Parallel()
	cases := map[int]string{
		http.StatusBadRequest:            "ValidationException",
		http.StatusMethodNotAllowed:      "ValidationException",
		http.StatusRequestEntityTooLarge: "ValidationException",
		http.StatusUnprocessableEntity:   "ValidationException",
		http.StatusUnauthorized:          "UnrecognizedClientException",
		http.StatusForbidden:             "AccessDeniedException",
		http.StatusNotFound:              "ResourceNotFoundException",
		http.StatusRequestTimeout:        "ModelTimeoutException",
		http.StatusFailedDependency:      "ModelErrorException",
		http.StatusTooManyRequests:       "ThrottlingException",
		http.StatusServiceUnavailable:    "ServiceUnavailableException",
		http.StatusInternalServerError:   "InternalServerException",
		http.StatusBadGateway:            "InternalServerException",
		http.StatusGatewayTimeout:        "InternalServerException",
	}
	for status, want := range cases {
		assert.Equal(t, want, BedrockErrorType(status), "status %d", status)
	}
}

func TestEncodeErrorBody_Bedrock(t *testing.T) {
	t.Parallel()
	assert.True(t, NeedsAdaptedError(FormatBedrock))
	assert.JSONEq(t, `{"__type":"AccessDeniedException","message":"nope"}`,
		string(EncodeErrorBody(FormatBedrock, http.StatusForbidden, "nope")))
	assert.JSONEq(t, `{"__type":"ThrottlingException","message":"Too Many Requests"}`,
		string(EncodeErrorBody(FormatBedrock, http.StatusTooManyRequests, "")))
}

func TestBedrockErrorEnvelope_MergesIntoTheGatewayBody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{
			name:   "gateway error keeps its own fields",
			status: http.StatusForbidden,
			body:   `{"error":"plugin_rejected","message":"blocked by policy","type":"guardrail_blocked"}`,
			want:   `{"__type":"AccessDeniedException","error":"plugin_rejected","message":"blocked by policy","type":"guardrail_blocked"}`,
		},
		{
			name:   "nested guardrail body takes its message from error.message",
			status: http.StatusForbidden,
			body:   `{"error":{"type":"guardrail_blocked","message":"Request blocked by guardrail.","policy":"topic_policy"}}`,
			want: `{"__type":"AccessDeniedException","error":{"type":"guardrail_blocked","message":"Request blocked by guardrail.","policy":"topic_policy"},` +
				`"message":"Request blocked by guardrail."}`,
		},
		{
			name:   "object with no message gets the status text",
			status: http.StatusTooManyRequests,
			body:   `{"retry_after":3}`,
			want:   `{"__type":"ThrottlingException","message":"Too Many Requests","retry_after":3}`,
		},
		{
			name:   "non string message is replaced",
			status: http.StatusBadRequest,
			body:   `{"message":{"detail":"x"},"error":"invalid_request"}`,
			want:   `{"__type":"ValidationException","error":"invalid_request","message":"Bad Request"}`,
		},
		{
			name:   "plain text becomes the message",
			status: http.StatusBadGateway,
			body:   `upstream exploded`,
			want:   `{"__type":"InternalServerException","message":"upstream exploded"}`,
		},
		{
			name:   "empty body",
			status: http.StatusServiceUnavailable,
			body:   ``,
			want:   `{"__type":"ServiceUnavailableException","message":"Service Unavailable"}`,
		},
		{
			name:   "a __type the body already carries is overridden by the status",
			status: http.StatusForbidden,
			body:   `{"__type":"Other","message":"x"}`,
			want:   `{"__type":"AccessDeniedException","message":"x"}`,
		},
		{
			name:   "json array body is wrapped",
			status: http.StatusBadRequest,
			body:   `[1,2]`,
			want:   `{"__type":"ValidationException","message":"Bad Request"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			headers, out := BedrockErrorEnvelope(tc.status, []byte(tc.body))
			assert.JSONEq(t, tc.want, string(out))
			var parsed map[string]any
			require.NoError(t, json.Unmarshal(out, &parsed))
			assert.Equal(t, []string{BedrockErrorType(tc.status)}, headers[HeaderAmznErrorType])
			assert.Equal(t, []string{"application/json"}, headers["Content-Type"])
		})
	}
}
