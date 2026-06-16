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

package ratelimit

// RateLimiterData is the per-invocation trace payload describing the evaluated
// rate-limit window and whether it was exceeded.
type RateLimiterData struct {
	RateLimitExceeded bool   `json:"rate_limit_exceeded"`
	ExceededType      string `json:"exceeded_type,omitempty"`
	RetryAfter        string `json:"retry_after,omitempty"`
	CurrentCount      int64  `json:"current_count"`
	Limit             int    `json:"limit"`
	Window            string `json:"window,omitempty"`
}
