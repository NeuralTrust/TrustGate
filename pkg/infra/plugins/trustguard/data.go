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

// GuardFinding is one TrustGuard finding in the guard wire contract.
type GuardFinding struct {
	Source   *GuardFindingSource  `json:"source,omitempty"`
	Signal   *GuardFindingSignal  `json:"signal,omitempty"`
	Outcome  *GuardFindingOutcome `json:"outcome,omitempty"`
	Evidence map[string]any       `json:"evidence,omitempty"`
}

type guardData struct {
	Direction      string         `json:"direction,omitempty"`
	Status         string         `json:"status,omitempty"`
	Decision       string         `json:"decision,omitempty"`
	TraceID        string         `json:"trace_id,omitempty"`
	RequestID      string         `json:"request_id,omitempty"`
	FindingsCount  int            `json:"findings_count,omitempty"`
	Findings       []GuardFinding `json:"findings,omitempty"`
	FailedOpen     bool           `json:"failed_open,omitempty"`
	Degraded       bool           `json:"degraded,omitempty"`
	DegradedReason string         `json:"degraded_reason,omitempty"`
}

func setExtras(event *metrics.EventContext, data guardData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

func recordGuardOutcome(event *metrics.EventContext, data guardData) {
	setExtras(event, data)
	if scoreLabelWorthy(data.Decision) {
		if label, score, ok := primaryFinding(data.Findings); ok {
			event.SetScore(score, label)
		}
	}
	appplugins.SetDecisionFromOutcome(event, data.Decision)
}

// scoreLabelWorthy reports whether a guard decision represents an actual
// detection worth surfacing in the Security Engine breakdown. Pass-through
// outcomes (allowed, failed_open) must not emit a score label.
func scoreLabelWorthy(decision string) bool {
	switch decision {
	case decisionBlocked, decisionReported, decisionTransformed:
		return true
	default:
		return false
	}
}

// primaryFinding selects the finding that best represents the guard decision for
// the Security Engine metric: the enforced detection with the highest
// confidence, falling back to the highest-confidence signal when nothing was
// enforced. It returns ok=false when no finding carries a usable signal type.
func primaryFinding(findings []GuardFinding) (label string, score float64, ok bool) {
	var enforced, any *GuardFinding
	for i := range findings {
		f := &findings[i]
		if f.Signal == nil || f.Signal.Type == "" {
			continue
		}
		if any == nil || f.Signal.Confidence > any.Signal.Confidence {
			any = f
		}
		if f.Outcome != nil && f.Outcome.Action != "" {
			if enforced == nil || f.Signal.Confidence > enforced.Signal.Confidence {
				enforced = f
			}
		}
	}
	chosen := enforced
	if chosen == nil {
		chosen = any
	}
	if chosen == nil {
		return "", 0, false
	}
	return chosen.Signal.Type, chosen.Signal.Confidence, true
}
