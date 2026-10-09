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
	"fmt"
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
// whether the answer is about the call's own configuration. A 400 about the
// model, the API version or the resource the policy names is config_invalid, and
// so is a 429 that is an exhausted quota (an account out of credit or at its
// billing limit) and not a rate: no request can change either, so refusing
// traffic for them would turn one bad setting into a 403 on every call. A 400
// whose body is not recognised as configuration stays input, since letting an
// unknown shape through would hand a client a way round the guardrail. A 429
// that is not recognised as a quota is a throttle. A 413 is always the
// content's.
func FailureOfRejection(status int, configShaped bool) (appplugins.FailureReason, string) {
	if configShaped {
		switch status {
		case http.StatusBadRequest:
			return appplugins.FailureConfigInvalid, appplugins.DetailProviderConfigRejected
		case http.StatusTooManyRequests:
			return appplugins.FailureConfigInvalid, appplugins.DetailProviderQuotaExhausted
		}
	}
	return FailureOfStatus(status)
}

// Rejection is implemented by the error a provider client returns for a non-2xx
// answer: the status, and whether the envelope says a 400 is about the call's
// own configuration or a 429 is an exhausted quota.
type Rejection interface {
	error
	Rejection() (status int, configShaped bool)
}

// AnswerTooLargeError is a provider answering 2xx with a body above what the
// client reads. Where the answer carries the request's text back (a mask), the
// request chose its size: JSON escaping alone grows a text of '<' six-fold, so a
// client can make the answer outgrow the limit and have the unmasked original
// forwarded as if the provider were down. It is therefore the input's, not the
// provider's availability.
type AnswerTooLargeError struct {
	Provider string
	Limit    int
}

func (e *AnswerTooLargeError) Error() string {
	return fmt.Sprintf("%s: response exceeds %d bytes", e.Provider, e.Limit)
}

// FailureOfError maps what a provider answered to the shared failure
// vocabulary: an AnswerTooLargeError is input, a Rejection is read through
// FailureOfRejection, and every other error (a timeout, a network error, an
// undecodable answer) is availability.
func FailureOfError(err error) (appplugins.FailureReason, string) {
	var tooLarge *AnswerTooLargeError
	if errors.As(err, &tooLarge) {
		return appplugins.FailureInputTooLarge, appplugins.DetailAnswerTooLarge
	}
	var rejection Rejection
	if errors.As(err, &rejection) {
		return FailureOfRejection(rejection.Rejection())
	}
	return appplugins.FailureTransport, ""
}

// FailureOfStatus maps a non-2xx provider status to the shared failure
// vocabulary: input when the provider refused the content, throttled when it
// answered 429, transport otherwise.
func FailureOfStatus(status int) (appplugins.FailureReason, string) {
	if StatusRejectsInput(status) {
		return appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput
	}
	if status == http.StatusTooManyRequests {
		return appplugins.FailureTransport, appplugins.DetailThrottled
	}
	return appplugins.FailureTransport, ""
}
