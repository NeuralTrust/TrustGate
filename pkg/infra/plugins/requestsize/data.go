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

package requestsize

// RequestSizeLimiterData is the per-invocation trace payload describing the
// measured request size and whether a configured limit was exceeded.
type RequestSizeLimiterData struct {
	RequestSizeBytes   int    `json:"request_size_bytes"`
	RequestSizeChars   int    `json:"request_size_chars"`
	MaxSizeBytes       int    `json:"max_size_bytes"`
	MaxCharsPerRequest int    `json:"max_chars_per_request"`
	LimitExceeded      bool   `json:"limit_exceeded"`
	ExceededType       string `json:"exceeded_type,omitempty"`
}
