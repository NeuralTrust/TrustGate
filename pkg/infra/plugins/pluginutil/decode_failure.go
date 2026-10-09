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
	// SkipReasonNonChatRoute is a request the route does not carry as chat JSON
	// (image, audio, file and multipart routes): there is no text for the
	// guardrail to judge.
	SkipReasonNonChatRoute = "non_chat_route"
)

// RequestDecodeFailure reports whether a request body that could not be turned
// into the canonical request an external guardrail reads is a failure of the
// input: a body the route promises to be chat JSON that does not parse as one
// is a client steering the call past the guardrail, so a blocking mode refuses
// it (decode_failed). Anything else is the route's own shape (an image, audio or
// file route has no chat decoder, and a multipart upload is not JSON): nothing
// the client got wrong and nothing for the guardrail to judge, so the leg is a
// recorded skip (SkipReasonNonChatRoute) and not a failure.
func RequestDecodeFailure(err error, capability string, format adapter.Format) bool {
	return adapter.IsRequestDecodeError(err) && adapter.IsChatRequest(capability, format)
}

// ResponseCarriesCompletion reports whether a buffered response is one a
// guardrail should read. pre_response also runs on what the upstream answered
// when it did not complete the call, and a 2xx status says the body is a
// completion; an unset status is a caller that does not carry one and is read.
func ResponseCarriesCompletion(resp *infracontext.ResponseContext) bool {
	return resp == nil || resp.StatusCode == 0 ||
		(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices)
}

// SkipWithoutCompletion records, and reports, that a buffered response is not a
// completion (see ResponseCarriesCompletion), so the caller passes it through.
func SkipWithoutCompletion(event *metrics.EventContext, stage string, resp *infracontext.ResponseContext) bool {
	if ResponseCarriesCompletion(resp) {
		return false
	}
	RecordSkipped(event, stage, SkipReasonUpstreamStatus)
	return true
}

// RecordSkipped marks, on the event's span, that a leg passed this policy
// uninspected and why, in the shape the console renders for every plugin.
func RecordSkipped(event *metrics.EventContext, stage, reason string) {
	if event == nil {
		return
	}
	event.SetExtras(skippedData{Stage: stage, Skipped: true, SkipReason: reason})
}
