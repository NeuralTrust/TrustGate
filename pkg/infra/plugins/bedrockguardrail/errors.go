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

package bedrockguardrail

import (
	"errors"
	"net/http"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

// notAboutTheInput are the AWS error types of a 4xx that say nothing about the
// content of the call: who is asking, how fast, and what the policy points at.
// The type is read rather than only the status because AWS answers some of them
// with a status that looks like a malformed request (ExpiredTokenException and
// ServiceQuotaExceededException are HTTP 400).
var notAboutTheInput = map[string]struct{}{
	// Credentials: missing, wrong, expired or not allowed.
	"AccessDeniedException":       {},
	"AccessDenied":                {},
	"UnrecognizedClientException": {},
	"ExpiredTokenException":       {},
	"ExpiredToken":                {},
	"InvalidSignatureException":   {},
	"IncompleteSignature":         {},
	"InvalidClientTokenId":        {},
	"MissingAuthenticationToken":  {},
	"SignatureDoesNotMatch":       {},
	"RequestExpired":              {},
	"NotAuthorized":               {},
	// Throttling and quotas.
	"ThrottlingException":           {},
	"Throttling":                    {},
	"ThrottledException":            {},
	"TooManyRequestsException":      {},
	"RequestLimitExceeded":          {},
	"ServiceQuotaExceededException": {},
	// The guardrail the policy names is not there: configuration, not content.
	"ResourceNotFoundException": {},
}

// classifyApplyErr maps what ApplyGuardrail answered to the shared failure
// vocabulary. A client error (4xx) the provider returns for what the call
// carries, a ValidationException above all, is the request's own content
// (input_too_large, provider_rejected_input). Everything else is the provider,
// the network or the credentials: transport, which fails open.
//
// The answer is classified on the AWS error type and the HTTP status, never on
// the message. The exact error AWS returns for an oversize text is not
// documented (the quotas page lists 25 text units in some regions and the API
// reference lists ValidationException among the errors without tying it to
// size), so a match on message text would be a guess that breaks when AWS
// rewords it, and one that fails closed on the wrong error.
func classifyApplyErr(err error) (appplugins.FailureReason, string) {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return appplugins.FailureTransport, ""
	}
	if _, skip := notAboutTheInput[api.ErrorCode()]; skip {
		return appplugins.FailureTransport, ""
	}
	status := 0
	var response *awshttp.ResponseError
	if errors.As(err, &response) {
		status = response.HTTPStatusCode()
	}
	switch {
	case status == 0:
		if api.ErrorFault() == smithy.FaultClient {
			return appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput
		}
	case status == http.StatusUnauthorized, status == http.StatusForbidden,
		status == http.StatusRequestTimeout, status == http.StatusTooManyRequests:
	case status >= http.StatusBadRequest && status < http.StatusInternalServerError:
		return appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput
	}
	return appplugins.FailureTransport, ""
}
