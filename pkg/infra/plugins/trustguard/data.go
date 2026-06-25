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

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type GuardRequest struct {
	Input      GuardInput      `json:"input"`
	Direction  string          `json:"direction"`
	Protocol   string          `json:"protocol"`
	GatewayID  string          `json:"gateway_id"`
	SessionID  string          `json:"session_id"`
	ConsumerID string          `json:"consumer_id"`
	Attributes GuardAttributes `json:"attributes"`
}

type GuardInput struct {
	Input       string            `json:"input"`
	Attachments []GuardAttachment `json:"attachments,omitempty"`
}

type GuardAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Data        string `json:"data,omitempty"`
	URL         string `json:"url,omitempty"`
}

type GuardAttributes struct {
	ContentType string     `json:"content_type"`
	Model       GuardModel `json:"model"`
}

type GuardModel struct {
	Name     string `json:"name,omitempty"`
	Provider string `json:"provider,omitempty"`
}

type GuardResponse struct {
	Status             string         `json:"status"`
	TransformedPayload map[string]any `json:"transformed_payload"`
	Findings           []GuardFinding `json:"findings"`
	TraceID            string         `json:"trace_id"`
	RequestID          string         `json:"request_id"`
}

type GuardFinding struct {
	DetectionType string  `json:"detection_type,omitempty"`
	Confidence    float64 `json:"confidence,omitempty"`
	RuleName      string  `json:"rule_name,omitempty"`
	Status        string  `json:"status,omitempty"`
	PolicyID      string  `json:"policy_id,omitempty"`
	DetectorID    string  `json:"detector_id,omitempty"`
	Action        string  `json:"action,omitempty"`
	Details       any     `json:"details,omitempty"`
}

type guardData struct {
	Direction     string `json:"direction,omitempty"`
	Status        string `json:"status,omitempty"`
	Decision      string `json:"decision,omitempty"`
	TraceID       string `json:"trace_id,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
	FindingsCount int    `json:"findings_count,omitempty"`
	FailedOpen    bool   `json:"failed_open,omitempty"`
}

func setExtras(event *metrics.EventContext, data guardData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}
