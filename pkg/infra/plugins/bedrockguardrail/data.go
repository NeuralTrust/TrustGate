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

package bedrockguardrail

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type Data struct {
	GuardrailID    string `json:"guardrail_id,omitempty"`
	Version        string `json:"version,omitempty"`
	Region         string `json:"region,omitempty"`
	Stage          string `json:"stage,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Decision       string `json:"decision,omitempty"`
	Policy         string `json:"policy,omitempty"`
	MatchType      string `json:"type,omitempty"`
	Action         string `json:"action,omitempty"`
	Name           string `json:"name,omitempty"`
	LatencyMS      int64  `json:"latency_ms,omitempty"`
	Degraded       bool   `json:"degraded,omitempty"`
	DegradedReason string `json:"degraded_reason,omitempty"`
}

func setExtras(event *metrics.EventContext, data *Data) {
	if event == nil || data == nil {
		return
	}
	event.SetExtras(data)
}
