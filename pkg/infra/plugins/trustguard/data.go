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
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

type GuardRequest struct {
	Payload    GuardPayload    `json:"payload"`
	Direction  string          `json:"direction"`
	Protocol   string          `json:"protocol"`
	GatewayID  string          `json:"gateway_id"`
	SessionID  string          `json:"session_id"`
	ConsumerID string          `json:"consumer_id"`
	Attributes GuardAttributes `json:"attributes"`
}

type GuardPayload struct {
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

// GuardFindingSource identifies who produced a guard finding.
type GuardFindingSource struct {
	Kind         string `json:"kind,omitempty"`
	Plugin       string `json:"plugin,omitempty"`
	DetectorID   string `json:"detector_id,omitempty"`
	DetectorName string `json:"detector_name,omitempty"`
	PolicyID     string `json:"policy_id,omitempty"`
	GateName     string `json:"gate_name,omitempty"`
}

// GuardFindingSignal is the detection signal when a plugin or gate matched.
type GuardFindingSignal struct {
	Type       string  `json:"type,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// GuardFindingOutcome is the enforcement action applied to a real detection.
type GuardFindingOutcome struct {
	Action string `json:"action,omitempty"`
}

// GuardFinding is one TrustGuard finding in the v2 wire contract.
type GuardFinding struct {
	Source   *GuardFindingSource  `json:"source,omitempty"`
	Signal   *GuardFindingSignal  `json:"signal,omitempty"`
	Outcome  *GuardFindingOutcome `json:"outcome,omitempty"`
	Evidence map[string]any       `json:"evidence,omitempty"`
}

type guardData struct {
	Direction     string         `json:"direction,omitempty"`
	Status        string         `json:"status,omitempty"`
	Decision      string         `json:"decision,omitempty"`
	TraceID       string         `json:"trace_id,omitempty"`
	RequestID     string         `json:"request_id,omitempty"`
	FindingsCount int            `json:"findings_count,omitempty"`
	Findings      []GuardFinding `json:"findings,omitempty"`
	FailedOpen    bool           `json:"failed_open,omitempty"`
}

func setExtras(event *metrics.EventContext, data guardData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

func recordGuardOutcome(event *metrics.EventContext, data guardData) {
	setExtras(event, data)
	appplugins.SetDecisionFromOutcome(event, data.Decision)
}
