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

import appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"

type TestConnectionResponse struct {
	OK         bool   `json:"ok"`
	Stage      string `json:"stage"`
	Provider   string `json:"provider"`
	StatusCode int    `json:"status_code,omitempty"`
	LatencyMs  int64  `json:"latency_ms"`
	Message    string `json:"message,omitempty"`
}

func FromTestConnectionResult(r appregistry.TestConnectionResult) TestConnectionResponse {
	return TestConnectionResponse{
		OK:         r.OK,
		Stage:      r.Stage,
		Provider:   r.Provider,
		StatusCode: r.StatusCode,
		LatencyMs:  r.LatencyMs,
		Message:    r.Message,
	}
}
