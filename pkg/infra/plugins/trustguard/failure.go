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

package trustguard

import appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"

const decisionFailedClosed = appplugins.DecisionFailedClosed

// sharedFailure maps this plugin's failure vocabulary, which predates the shared
// one and is what its metrics and telemetry carry, onto the (reason, detail)
// pair appplugins.ClassOf classifies. The class is never decided here: a reason
// this plugin adds later and does not map is availability, so it cannot start
// refusing traffic by omission.
//
// Only five of its reasons say something about the request itself. A payload
// this plugin could not build is a body it could not read (decode_failed). A 413
// is the body TrustGuard refused for its size, and a 400 "invalid attachment" is
// an attachment it could not fetch or decode. An answer above the size the
// client reads is the request's too: the mask echoes its text back. A transform it cannot write back
// is a mask over a finding TrustGuard confirmed, which the detail says.
func sharedFailure(reason, transformReason string) (appplugins.FailureReason, string) {
	switch reason {
	case failureReasonPayloadUnreadable:
		return appplugins.FailureDecodeFailed, ""
	case failureReasonPayloadTooLarge:
		return appplugins.FailureInputTooLarge, appplugins.DetailPayloadTooLarge
	case failureReasonResponseTooLarge:
		return appplugins.FailureInputTooLarge, appplugins.DetailAnswerTooLarge
	case failureReasonAttachmentRejected:
		return appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput
	case failureReasonTransformFailed:
		return appplugins.FailureVerdictIncomplete, maskDetailOf(transformReason)
	default:
		return appplugins.FailureTransport, ""
	}
}

func maskDetailOf(transformReason string) string {
	switch transformReason {
	case reasonTransformNoPayload:
		return appplugins.DetailAnonymizeNoOutput
	case reasonTransformUnsupported:
		return appplugins.DetailAnonymizeUnsupportedFmt
	default:
		return appplugins.DetailAnonymizeEncodeFailed
	}
}

// transformReasonOf is maskDetailOf's inverse, for the degraded_reason a stream
// cut publishes in this plugin's own words.
func transformReasonOf(detail string) string {
	switch detail {
	case appplugins.DetailAnonymizeNoOutput:
		return reasonTransformNoPayload
	case appplugins.DetailAnonymizeUnsupportedFmt:
		return reasonTransformUnsupported
	default:
		return reasonTransformEncodeFailed
	}
}

// failureOfCut is the reason, in this plugin's vocabulary, and the class of the
// failure that authored a stream cut.
func failureOfCut(r appplugins.StreamReport) (reason, class string) {
	switch {
	case appplugins.IsMaskOverFinding(r.FailureDetail):
		reason = failureReasonTransformFailed
	case r.FailureReason == appplugins.FailureInputTooLarge && r.FailureDetail == appplugins.DetailPayloadTooLarge:
		reason = failureReasonPayloadTooLarge
	case r.FailureReason == appplugins.FailureInputTooLarge && r.FailureDetail == appplugins.DetailAnswerTooLarge:
		reason = failureReasonResponseTooLarge
	case r.FailureReason == appplugins.FailureInputTooLarge && r.FailureDetail == appplugins.DetailProviderRejectedInput:
		reason = failureReasonAttachmentRejected
	default:
		reason = string(r.FailureReason)
	}
	return reason, string(r.FailureClass)
}
