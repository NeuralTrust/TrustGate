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
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

// StatusRejectsInput reports whether a provider's HTTP status says it refused
// the content of the call: a 400 (the request, as sent, is not acceptable) or a
// 413 (it is too large). Credentials (401, 403), a timeout (408), throttling
// (429) and every 5xx are the provider's availability and are not it.
func StatusRejectsInput(status int) bool {
	return status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge
}

// FailureOfStatus maps a non-2xx provider status to the shared failure
// vocabulary: input when the provider refused the content, transport otherwise.
func FailureOfStatus(status int) (appplugins.FailureReason, string) {
	if StatusRejectsInput(status) {
		return appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput
	}
	return appplugins.FailureTransport, ""
}
