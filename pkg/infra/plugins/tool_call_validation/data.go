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

package tool_call_validation

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type ToolCallValidationData struct {
	Validator         string `json:"validator,omitempty"`
	Action            string `json:"action,omitempty"`
	ToolName          string `json:"tool_name,omitempty"`
	SemanticReasoning string `json:"semantic_reasoning,omitempty"`
	Degraded          bool   `json:"degraded,omitempty"`
	DegradedReason    string `json:"degraded_reason,omitempty"`
}

func setExtras(event *metrics.EventContext, data ToolCallValidationData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}
