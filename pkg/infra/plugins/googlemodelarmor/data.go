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

package googlemodelarmor

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type Data struct {
	Project        string   `json:"project,omitempty"`
	Location       string   `json:"location,omitempty"`
	Template       string   `json:"template,omitempty"`
	Stage          string   `json:"stage,omitempty"`
	Mode           string   `json:"mode,omitempty"`
	Decision       string   `json:"decision,omitempty"`
	Filter         string   `json:"filter,omitempty"`
	InfoTypes      []string `json:"info_types,omitempty"`
	LatencyMS      int64    `json:"latency_ms,omitempty"`
	Degraded       bool     `json:"degraded,omitempty"`
	DegradedReason string   `json:"degraded_reason,omitempty"`
	// FilterVersion is the Model Armor filter version that produced the
	// verdict. A template pointed at an alias rather than a pinned version
	// changes behaviour when Google promotes a new one, with no deploy on our
	// side, so without this "it used to block this and now it does not" has
	// no answer anyone can reach from our telemetry.
	FilterVersion string `json:"filter_version,omitempty"`
}

func setExtras(event *metrics.EventContext, data *Data) {
	if event == nil || data == nil {
		return
	}
	event.SetExtras(data)
}

// recordScore surfaces the matched Model Armor filter on the metrics span so
// it feeds the analytics Security Engine breakdown. Model Armor's REST API
// does not return a confidence score alongside filterMatchState, so only the
// label (the SDP info type when present, falling back to the filter name) is
// meaningful and the numeric score stays 0.
func recordScore(event *metrics.EventContext, data *Data) {
	if event == nil || data == nil {
		return
	}
	label := data.Filter
	if len(data.InfoTypes) > 0 && data.InfoTypes[0] != "" {
		label = data.InfoTypes[0]
	}
	if label == "" {
		return
	}
	event.SetScore(0, label)
}
