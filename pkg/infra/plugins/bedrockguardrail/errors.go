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
	"regexp"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
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
	"ThrottlingException":      {},
	"Throttling":               {},
	"ThrottledException":       {},
	"TooManyRequestsException": {},
	"RequestLimitExceeded":     {},
	// ServiceQuotaExceededException is the account's quota (on-demand text units
	// per second, per region), which no request content decides. An oversize
	// text is reported by GuardrailCoverage or a ValidationException instead.
	"ServiceQuotaExceededException": {},
	// The guardrail the policy names is not there: configuration, not content.
	"ResourceNotFoundException": {},
}

// throttlingErrors are the AWS error types of the account's per-second quota
// answering, which are availability and never evidence about the content.
// ServiceQuotaExceededException is an HTTP 400 that is the same quota.
var throttlingErrors = map[string]struct{}{
	"ThrottlingException":           {},
	"Throttling":                    {},
	"ThrottledException":            {},
	"TooManyRequestsException":      {},
	"RequestLimitExceeded":          {},
	"ServiceQuotaExceededException": {},
}

// isThrottled reports whether err is the quota answering.
func isThrottled(err error) bool {
	_, detail := classifyApplyErr(err)
	return detail == appplugins.DetailThrottled
}

// classifyApplyErr maps what ApplyGuardrail answered to the shared failure
// vocabulary. A client error (4xx) that ApplyGuardrail itself returns for what
// the call carries, a ValidationException above all, is the request's own
// content (input_too_large, provider_rejected_input). Everything else is the
// provider, the network, the credentials or the policy's own configuration:
// transport or config_invalid, which fail open.
//
// Only an error raised by the ApplyGuardrail operation can be about the input.
// A role that cannot be assumed surfaces from the same call wrapped by the
// signer, and STS answers a malformed role_arn or session_name with the very
// ValidationError a content problem would produce, so the credential chain is
// told apart before the answer is read. A ValidationException that names the
// guardrail identifier or version is the policy pointing at a guardrail AWS
// cannot take, which no request can change, so it is config_invalid.
//
// The answer is classified on the AWS error type, the HTTP status and, for the
// guardrail reference only, the members a ValidationException names, never on
// the rest of the message. The exact error
// AWS returns for an oversize text is not documented (the quotas page lists 25
// text units in some regions and the API reference lists ValidationException
// among the errors without tying it to size), so a match on message text would
// be a guess that breaks when AWS rewords it.
func classifyApplyErr(err error) (appplugins.FailureReason, string) {
	if !raisedByApplyGuardrail(err) {
		return appplugins.FailureTransport, ""
	}
	var api smithy.APIError
	if !errors.As(err, &api) {
		return appplugins.FailureTransport, ""
	}
	if _, throttled := throttlingErrors[api.ErrorCode()]; throttled {
		return appplugins.FailureTransport, appplugins.DetailThrottled
	}
	if _, skip := notAboutTheInput[api.ErrorCode()]; skip {
		return appplugins.FailureTransport, ""
	}
	if api.ErrorCode() == "ValidationException" && namesGuardrailReference(api.ErrorMessage()) {
		return appplugins.FailureConfigInvalid, appplugins.DetailProviderConfigRejected
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
	case status == http.StatusTooManyRequests:
		return appplugins.FailureTransport, appplugins.DetailThrottled
	case status == http.StatusUnauthorized, status == http.StatusForbidden,
		status == http.StatusRequestTimeout:
	case status >= http.StatusBadRequest && status < http.StatusInternalServerError:
		return appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput
	}
	return appplugins.FailureTransport, ""
}

// raisedByApplyGuardrail reports whether err is the answer of the
// ApplyGuardrail operation and not of the credential chain that signs it. The
// SDK wraps a failed credential fetch in a signing error and the fetch's own
// operation (STS AssumeRole) in a nested operation error, so the innermost
// operation names who answered.
func raisedByApplyGuardrail(err error) bool {
	var signing *v4.SigningError
	if errors.As(err, &signing) {
		return false
	}
	var innermost *smithy.OperationError
	for e := err; e != nil; e = errors.Unwrap(e) {
		if op, ok := e.(*smithy.OperationError); ok {
			innermost = op
		}
	}
	return innermost == nil || innermost.OperationName == applyGuardrailOperation
}

const applyGuardrailOperation = "ApplyGuardrail"

// constraintMember captures the member of every "at '<member>' failed to satisfy
// constraint" clause of an AWS validation error, whatever precedes it: AWS
// writes "Value '<v>' at", "Value at" or "Value null at" depending on what the
// caller sent, and the echoed value can hold newlines.
var constraintMember = regexp.MustCompile(`(?s)at '([^']*)' failed to satisfy constraint`)

// namesGuardrailReference reports whether a ValidationException is about the
// guardrail identifier or version the policy configures and about nothing
// else. AWS echoes the offending value, so client content can spell a
// guardrail clause inside the message; but AWS's own clause for a content
// member is always present and a client cannot remove it. Every clause in the
// message is therefore counted, and the rejection is the policy's only when
// each one names the identifier or the version. Any other member, the content
// above all, makes it the input's.
func namesGuardrailReference(message string) bool {
	members := constraintMember.FindAllStringSubmatch(message, -1)
	if len(members) == 0 {
		return false
	}
	for _, m := range members {
		if m[1] != "guardrailIdentifier" && m[1] != "guardrailVersion" {
			return false
		}
	}
	return true
}
