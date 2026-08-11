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

package azurecontentsafety

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type Data struct {
	Endpoint   string         `json:"endpoint,omitempty"`
	OutputType string         `json:"output_type,omitempty"`
	Severities map[string]int `json:"severities,omitempty"`
	Breached   []string       `json:"breached_categories,omitempty"`
	Decision   string         `json:"decision,omitempty"`
	Mode       string         `json:"mode,omitempty"`
	LatencyMS  int64          `json:"latency_ms,omitempty"`
	FailedOpen bool           `json:"failed_open,omitempty"`
}

func setExtras(event *metrics.EventContext, data *Data) {
	if event == nil || data == nil {
		return
	}
	event.SetExtras(data)
}

// azureSeverityScale is Azure Content Safety's maximum severity level. Scores
// are normalized to 0..1 so they are comparable with the confidence-style scores
// other security engines report.
const azureSeverityScale = 7

// recordScore surfaces the most severe breached category on the metrics span so
// it feeds the analytics Security Engine breakdown.
func recordScore(event *metrics.EventContext, breaches []breachedCategory) {
	if event == nil || len(breaches) == 0 {
		return
	}
	top := breaches[0]
	for _, b := range breaches[1:] {
		if b.Severity > top.Severity {
			top = b
		}
	}
	if top.Category == "" {
		return
	}
	event.SetScore(float64(top.Severity)/azureSeverityScale, top.Category)
}
