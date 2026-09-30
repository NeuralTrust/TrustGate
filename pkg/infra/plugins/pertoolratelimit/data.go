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

package pertoolratelimit

const rateLimitTemplate = "The tool %q (call %s) is rate limited and was not executed. Please slow down and retry later."

// Skip reasons a Per-Tool Rate Limiter records when it ran but had nothing to
// evaluate. Same keys TrustGuard uses (skipped / skip_reason), so a consumer
// parses one shape for both plugins.
const (
	skipReasonNoTools        = "no_tools"
	skipReasonNoMatchingRule = "no_matching_rule"
)

// skippedData is the extras of a call the plugin ran on but did not evaluate:
// the request declared no tools, or none matches a rule. It carries no
// decision, so the entry reads as neither allowed nor blocked. Without it the
// span is dropped by the metrics builder as a no-op and the policy looks
// unattached.
type skippedData struct {
	Stage      string `json:"stage"`
	Skipped    bool   `json:"skipped"`
	SkipReason string `json:"skip_reason"`
}

type PerToolRateLimiterData struct {
	Stage         string `json:"stage"`
	CounterKey    string `json:"counter_key"`
	Tool          string `json:"tool"`
	ToolCallID    string `json:"tool_call_id,omitempty"`
	Dimension     string `json:"dimension"`
	Subject       string `json:"subject"`
	WindowMax     int    `json:"window_max"`
	WindowSeconds int    `json:"window_seconds"`
	CurrentCount  int    `json:"current_count"`
	Behavior      string `json:"behavior"`
	LimitExceeded bool   `json:"limit_exceeded"`
	// FailureReason and FailureDetail are set only on a failed_open decision:
	// the counter store (Redis) could not be read or written. FailureReason is
	// always appplugins.FailureCounterUnavailable; FailureDetail names which
	// call failed ("read" or "record").
	FailureReason string `json:"failure_reason,omitempty"`
	FailureDetail string `json:"failure_detail,omitempty"`
}
