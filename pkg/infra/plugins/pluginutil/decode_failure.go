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
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// Skip reasons of the legs an external guardrail did not inspect because what
// reached it is not content it was asked to judge.
const (
	// SkipReasonUpstreamStatus is a response the upstream answered with a
	// non-2xx status: an error envelope, an error page from a proxy in front of
	// it, a throttle. It carries no completion.
	SkipReasonUpstreamStatus = "upstream_error_status"
	// SkipReasonUndecodableResponse is a 2xx response whose body no adapter
	// reads as a completion, such as the audio bytes of a speech route.
	SkipReasonUndecodableResponse = "undecodable_response"
)

// RequestDecodeFailure classifies why a request body could not be turned into
// the canonical request an external guardrail reads. It is input only when a
// body the route promises to be chat JSON does not parse as one: that is a
// client steering the call past the guardrail, so a blocking mode refuses it.
// Everything else is the route's own shape (an image, audio or file route has
// no chat decoder, and a multipart upload is not JSON), which is
// config_invalid with unsupported_format: nothing the client got wrong, so the
// call goes through uninspected as an availability failure.
func RequestDecodeFailure(err error, capability string, format adapter.Format) (appplugins.FailureReason, string) {
	if adapter.IsRequestDecodeError(err) && adapter.IsChatRequest(capability, format) {
		return appplugins.FailureDecodeFailed, ""
	}
	return appplugins.FailureConfigInvalid, appplugins.DetailUnsupportedFormat
}

// ResponseCarriesCompletion reports whether a buffered response is one a
// guardrail should read. pre_response also runs on what the upstream answered
// when it did not complete the call, and a 2xx status says the body is a
// completion; an unset status is a caller that does not carry one and is read.
func ResponseCarriesCompletion(resp *infracontext.ResponseContext) bool {
	return resp == nil || resp.StatusCode == 0 ||
		(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices)
}

// RecordSkipped marks, on the event's span, that a leg passed this policy
// uninspected and why, in the shape the console renders for every plugin.
func RecordSkipped(event *metrics.EventContext, stage, reason string) {
	if event == nil {
		return
	}
	event.SetExtras(skippedData{Stage: stage, Skipped: true, SkipReason: reason})
}
