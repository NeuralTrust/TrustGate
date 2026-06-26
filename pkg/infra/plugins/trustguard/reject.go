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

const blockMessage = "request blocked by TrustGuard"

func blockError(resp *GuardResponse) *appplugins.PluginError {
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Type:       typeBlocked,
		Message:    blockMessage,
		Body:       blockBody(resp),
	}
}

func blockBody(resp *GuardResponse) []byte {
	body := struct {
		Status    string         `json:"status"`
		Message   string         `json:"message"`
		Findings  []GuardFinding `json:"findings,omitempty"`
		TraceID   string         `json:"trace_id,omitempty"`
		RequestID string         `json:"request_id,omitempty"`
	}{
		Status:  blockMessage,
		Message: blockMessage,
	}
	if resp != nil {
		body.Status = resp.Status
		body.Findings = resp.Findings
		body.TraceID = resp.TraceID
		body.RequestID = resp.RequestID
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return []byte(blockMessage)
	}
	return raw
}
