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

package tokenratelimit

// TokenRateLimiterData is the per-invocation trace payload describing the token
// budget window and the tokens consumed/remaining at each stage.
type TokenRateLimiterData struct {
	Stage           string `json:"stage"`
	CounterKey      string `json:"counter_key"`
	Provider        string `json:"provider,omitempty"`
	WindowUnit      string `json:"window_unit"`
	WindowMax       int    `json:"window_max"`
	TokensConsumed  int    `json:"tokens_consumed"`
	TokensActual    int    `json:"tokens_actual,omitempty"`
	TokensRemaining int    `json:"tokens_remaining"`
	LimitExceeded   bool   `json:"limit_exceeded"`
}
