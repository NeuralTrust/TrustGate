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

package trustguard

import (
	"encoding/json"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

const typeBlocked = "trustguard_blocked"
const typeRateLimited = "trustguard_rate_limited"

const blockMessage = "request blocked due to a policy infraction"
const rateLimitMessage = "rate limit exceeded"

func blockError(resp *GuardResponse) *appplugins.PluginError {
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Type:       typeBlocked,
		Message:    blockMessage,
		Body:       blockBody(resp),
	}
}

func rateLimitError(err *rateLimitedError) *appplugins.PluginError {
	body := err.body
	if len(body) == 0 {
		body = []byte(`{"error":"rate limit exceeded"}`)
	}
	return &appplugins.PluginError{
		StatusCode: http.StatusTooManyRequests,
		Type:       typeRateLimited,
		Message:    rateLimitMessage,
		Headers:    err.headers,
		Body:       body,
	}
}

func blockBody(resp *GuardResponse) []byte {
	body := struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		TraceID   string `json:"trace_id,omitempty"`
		RequestID string `json:"request_id,omitempty"`
	}{
		Status:  statusBlock,
		Message: blockMessage,
	}
	if resp != nil {
		if resp.Status != "" {
			body.Status = resp.Status
		}
		body.TraceID = resp.TraceID
		body.RequestID = resp.RequestID
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"status":"block","message":"request blocked due to a policy infraction"}`)
	}
	return raw
}
