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

package cors

// CorsData is the per-invocation trace payload describing the CORS decision.
type CorsData struct {
	Origin          string   `json:"origin"`
	Method          string   `json:"method"`
	Preflight       bool     `json:"preflight"`
	Allowed         bool     `json:"allowed"`
	RequestedMethod string   `json:"requested_method,omitempty"`
	AllowedMethods  []string `json:"allowed_methods,omitempty"`
}
