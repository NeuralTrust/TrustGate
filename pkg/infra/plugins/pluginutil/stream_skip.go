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

package pluginutil

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

// SkipReasonStreamingDisabled is the skip_reason recorded when a streamed
// response was not inspected because streaming is switched off for the policy.
const SkipReasonStreamingDisabled = "streaming_disabled"

// skippedData is the extras of a leg the plugin ran on and did not inspect. The
// keys match pertoolratelimit's and trustguard's skip marker, so the console
// renders it without knowing which plugin wrote it. Without it the span is
// dropped by the metrics builder as a no-op and the policy looks unattached.
type skippedData struct {
	Stage      string `json:"stage"`
	Skipped    bool   `json:"skipped"`
	SkipReason string `json:"skip_reason"`
}

// RecordStreamingDisabled marks, on the event's span, that a streamed response
// passed this policy uninspected because its streaming is disabled.
func RecordStreamingDisabled(event *metrics.EventContext, stage string) {
	if event == nil {
		return
	}
	event.SetExtras(skippedData{Stage: stage, Skipped: true, SkipReason: SkipReasonStreamingDisabled})
}
