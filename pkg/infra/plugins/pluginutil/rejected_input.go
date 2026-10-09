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
	"errors"
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

// FailureOfRejection is FailureOfStatus for a provider whose error body says
// whether a 400 is about the content or about the call's own configuration (the
// model, the API version, the resource the policy names). A configuration
// rejection is config_invalid, which is availability: no request can change it,
// so refusing traffic for it would turn one bad setting into a 403 on every
// call. A 400 whose body is not recognised as configuration stays input, since
// letting an unknown shape through would hand a client a way round the
// guardrail. A 413 is always the content's.
func FailureOfRejection(status int, configShaped bool) (appplugins.FailureReason, string) {
	if status == http.StatusBadRequest && configShaped {
		return appplugins.FailureConfigInvalid, appplugins.DetailProviderConfigRejected
	}
	return FailureOfStatus(status)
}

// Rejection is implemented by the error a provider client returns for a non-2xx
// answer: the status, and whether a 400's envelope says it is about the call's
// own configuration.
type Rejection interface {
	error
	Rejection() (status int, configShaped bool)
}

// FailureOfError maps what a provider answered to the shared failure
// vocabulary: a Rejection is read through FailureOfRejection, and every other
// error (a timeout, a network error, an undecodable answer) is availability.
func FailureOfError(err error) (appplugins.FailureReason, string) {
	var rejection Rejection
	if errors.As(err, &rejection) {
		return FailureOfRejection(rejection.Rejection())
	}
	return appplugins.FailureTransport, ""
}

// FailureOfStatus maps a non-2xx provider status to the shared failure
// vocabulary: input when the provider refused the content, transport otherwise.
func FailureOfStatus(status int) (appplugins.FailureReason, string) {
	if StatusRejectsInput(status) {
		return appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput
	}
	return appplugins.FailureTransport, ""
}
