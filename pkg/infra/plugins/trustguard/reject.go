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
	"fmt"
	"net/http"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

const typeBlocked = "trustguard_blocked"
const typeRateLimited = "trustguard_rate_limited"

const blockMessage = "request blocked due to a policy infraction"
const rateLimitMessage = "rate limit exceeded"

// blockError renders a TrustGuard block. direction ("input" or "output") says
// which leg of the exchange was blocked; it travels in the body so an
// integrator can tell a blocked prompt from a blocked completion.
func blockError(resp *GuardResponse, direction string) *appplugins.PluginError {
	message := clientBlockMessage(resp)
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Type:       typeBlocked,
		Message:    message,
		Body:       blockBody(resp, message, direction),
	}
}

func rateLimitError(err *rateLimitedError) *appplugins.PluginError {
	body := err.body
	if len(body) == 0 {
		body = []byte(`{"error":"rate limit exceeded","message":"Request blocked: rate limit exceeded."}`)
	}
	return &appplugins.PluginError{
		StatusCode: http.StatusTooManyRequests,
		Type:       typeRateLimited,
		Message:    rateLimitMessage,
		Headers:    err.headers,
		Body:       body,
	}
}

func blockBody(resp *GuardResponse, message, direction string) []byte {
	if message == "" {
		message = blockMessage
	}
	body := struct {
		Status       string `json:"status"`
		Message      string `json:"message"`
		Type         string `json:"type,omitempty"`
		Direction    string `json:"direction,omitempty"`
		Reason       string `json:"reason,omitempty"`
		Plugin       string `json:"plugin,omitempty"`
		DetectorName string `json:"detector_name,omitempty"`
		GateName     string `json:"gate_name,omitempty"`
		TraceID      string `json:"trace_id,omitempty"`
		RequestID    string `json:"request_id,omitempty"`
	}{
		Status:    statusBlock,
		Message:   message,
		Type:      typeBlocked,
		Direction: direction,
	}
	if resp != nil {
		if resp.Status != "" {
			body.Status = resp.Status
		}
		body.TraceID = resp.TraceID
		body.RequestID = resp.RequestID
		if finding := selectPrimaryFinding(resp.Findings); finding != nil {
			if finding.Signal != nil {
				body.Reason = finding.Signal.Type
			}
			if finding.Source != nil {
				body.Plugin = finding.Source.Plugin
				body.DetectorName = finding.Source.DetectorName
				body.GateName = finding.Source.GateName
			}
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"status":"block","message":"request blocked due to a policy infraction","type":"trustguard_blocked"}`)
	}
	return raw
}

func clientBlockMessage(resp *GuardResponse) string {
	if resp == nil {
		return blockMessage
	}
	finding := selectPrimaryFinding(resp.Findings)
	if finding == nil {
		return blockMessage
	}
	reason := ""
	if finding.Signal != nil {
		reason = strings.TrimSpace(finding.Signal.Type)
	}
	name := ""
	if finding.Source != nil {
		name = strings.TrimSpace(finding.Source.DetectorName)
		if name == "" {
			name = strings.TrimSpace(finding.Source.GateName)
		}
	}
	switch {
	case reason != "" && name != "":
		return fmt.Sprintf("Request blocked by security policy: %s (%s).", reason, name)
	case reason != "":
		return fmt.Sprintf("Request blocked by security policy: %s.", reason)
	case name != "":
		return fmt.Sprintf("Request blocked by security policy (%s).", name)
	default:
		return blockMessage
	}
}
