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

package response

import apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"

// TestConnectionResponse is the outcome of a policy connection test. Code is
// stable for clients to map; Message is display text without credentials.
type TestConnectionResponse struct {
	OK        bool   `json:"ok"`
	Code      string `json:"code" example:"permission_denied"`
	Message   string `json:"message"`
	LatencyMs int64  `json:"latency_ms"`
}

func FromTestConnectionResult(r apppolicy.TestConnectionResult) TestConnectionResponse {
	return TestConnectionResponse{OK: r.OK, Code: r.Code, Message: r.Message, LatencyMs: r.Latency.Milliseconds()}
}
