// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package response

import appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"

// TestSecretResponse is the outcome of a test; it never carries the value.
type TestSecretResponse struct {
	// Auth is "ok" or the error class of authenticating to the store.
	Auth string `json:"auth" example:"ok"`
	// Read is "ok", "skipped" or the error class of the read.
	Read      string `json:"read" example:"ok"`
	Version   string `json:"version,omitempty" example:"3"`
	LatencyMS int64  `json:"latency_ms" example:"42"`
}

// FromTestResult builds the test response.
func FromTestResult(r appsecretstore.TestResult) TestSecretResponse {
	return TestSecretResponse{Auth: r.Auth, Read: r.Read, Version: r.Version, LatencyMS: r.Latency.Milliseconds()}
}
