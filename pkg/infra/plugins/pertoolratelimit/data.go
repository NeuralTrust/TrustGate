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

type PerToolRateLimiterData struct {
	Stage         string `json:"stage"`
	CounterKey    string `json:"counter_key"`
	Tool          string `json:"tool"`
	Dimension     string `json:"dimension"`
	Subject       string `json:"subject"`
	WindowMax     int    `json:"window_max"`
	WindowSeconds int    `json:"window_seconds"`
	CurrentCount  int    `json:"current_count"`
	Behavior      string `json:"behavior"`
	LimitExceeded bool   `json:"limit_exceeded"`
}
