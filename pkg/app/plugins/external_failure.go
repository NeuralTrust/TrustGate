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

package plugins

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

// FailureReason names why a third-party (external) guardrail call did not
// produce a verdict the chain can act on. It is the shared taxonomy every
// external guardrail (azure_content_safety, bedrock_guardrail,
// google_model_armor, openai_moderation) records on its own Data, so an
// operator reading one plugin's telemetry already knows the vocabulary for
// the other three.
type FailureReason string

const (
	// FailureTransport is a network or API failure calling the guardrail: a
	// connection error, a non-2xx response, or a timeout or throttle, which
	// are reported as transport rather than under reasons of their own.
	FailureTransport FailureReason = "transport"
	// FailureVerdictIncomplete is a response the guardrail returned that does
	// not cover everything the policy asked it to evaluate: a thresholded
	// category missing from the response, an intervention the plugin has no
	// finding to explain, a filter selected in block_on that never ran.
	// It is a failure like a transport one, not a clean "no match", so it is
	// recorded as failed_open with this reason rather than as a pass.
	FailureVerdictIncomplete FailureReason = "verdict_incomplete"
	// FailureConfigInvalid is a stored policy configuration the plugin
	// cannot act on at run time: parseConfig rejected the settings, or a
	// client could not be built for the configured credentials. It can reach
	// a running policy that validated at save time under older rules, so it
	// is handled at run time rather than surfaced only at write time.
	FailureConfigInvalid FailureReason = "config_invalid"
	// FailureDecodeFailed is our own side failing to decode the request or
	// response body before the guardrail ever saw it. The guardrail was
	// never consulted, so there was nothing for it to say.
	FailureDecodeFailed FailureReason = "decode_failed"
	// FailureCounterUnavailable is TrustGate's own counter store (Redis)
	// failing a read or a write: rate_limiter, per_tool_rate_limiter and
	// token_rate_limiter all share this one reason. It is handled by
	// HandleCounterFailure in counter_failure.go, not by HandleExternalFailure;
	// token_rate_limiter with partition key fails closed there on a read in a
	// blocking mode.
	FailureCounterUnavailable FailureReason = "counter_unavailable"
)

// DecisionFailedOpen is the decision recorded when a guardrail could not give
// a verdict and the traffic was let through. The buffered legs and the stream
// leg share it.
const DecisionFailedOpen = "failed_open"

// ExternalFailure is one third-party guardrail call's failure, ready to be
// turned into a plugin outcome by HandleExternalFailure.
type ExternalFailure struct {
	Ctx    context.Context
	Plugin string
	Stage  policy.Stage
	Mode   policy.Mode
	Reason FailureReason
	// Detail is optional context named in the Warn log — typically the
	// filter or category the guardrail left unanswered. It is not written
	// onto any Data struct by this helper: the caller decides where (if
	// anywhere) its own Data carries it.
	Detail string
	Err    error
	Logger *slog.Logger
	Event  *metrics.EventContext
}

// ExternalFailureOutcome is HandleExternalFailure's answer. Decision is what
// the caller's own Data.Decision (and any failure_reason/failure_detail
// fields) should record; Result and Err are exactly what the plugin's
// Execute should return. Err is always nil today: an external guardrail
// failure never refuses the request.
type ExternalFailureOutcome struct {
	Decision string
	Result   *Result
	Err      error
}

// HandleExternalFailure applies the one rule every external guardrail
// follows on a failure of its buffered (non-streamed) leg: it fails OPEN, in
// every mode (enforce, throttle and observe) and for every FailureReason
// (transport, which also covers timeouts and throttling, verdict_incomplete,
// config_invalid and decode_failed). The request continues and the event
// records decision failed_open with the failure_reason (and failure_detail)
// the caller sets on its own Data. A guardrail we cannot reach never refuses a
// buffered request (RUN-1792, replacing the RUN-1672 rule). The stream leg is
// covered separately by RUN-1786.
//
// TrustGuard does not go through this helper: its failures, credential errors
// included, follow its own on_error setting inside the trustguard plugin.
//
// This only decides the outcome, sets the chain-level span decision via
// SetDecisionFromOutcome, and emits the one Warn log the failure gets. The
// caller still owns its own Data: it is responsible for setting
// Data.Decision (from ExternalFailureOutcome.Decision) and any
// failure_reason/failure_detail fields, and calling setExtras, before or
// after invoking this.
func HandleExternalFailure(f ExternalFailure) ExternalFailureOutcome {
	outcome := ExternalFailureOutcome{
		Decision: DecisionFailedOpen,
		Result:   &Result{StatusCode: http.StatusOK},
	}
	SetDecisionFromOutcome(f.Event, outcome.Decision)
	logExternalFailure(f, outcome.Decision)
	return outcome
}

func logExternalFailure(f ExternalFailure, decision string) {
	if f.Logger == nil {
		return
	}
	attrs := []any{
		slog.String("plugin", f.Plugin),
		slog.String("stage", string(f.Stage)),
		slog.String("mode", string(f.Mode)),
		slog.String("reason", string(f.Reason)),
		slog.String("decision", decision),
	}
	if f.Detail != "" {
		attrs = append(attrs, slog.String("detail", f.Detail))
	}
	if f.Err != nil {
		attrs = append(attrs, slog.Any("error", f.Err))
	}
	if f.Ctx != nil {
		f.Logger.WarnContext(f.Ctx, "external guardrail call failed", attrs...)
		return
	}
	f.Logger.Warn("external guardrail call failed", attrs...)
}

// WrapExternalStreamFailure formats a stream-segment failure so its reason
// (and, when present, detail) travel in the error text.
//
// Unlike HandleExternalFailure, a streamed segment's fail-open/fail-closed
// choice is not the plugin's mode to make: the stream guard already owns
// that decision through streaming.on_error (pkg/app/proxy/stream_guard.go),
// because only the guard knows whether anything has been released to the
// client yet, which is what turns fail_closed into a clean status code
// instead of a truncated body. The guard also already logs the returned
// error itself (headFailure/blockFailure), so this does not log again: doing
// so would print the same failure twice for one segment. It only gives that
// one log line the same reason vocabulary HandleExternalFailure uses.
func WrapExternalStreamFailure(pluginName string, reason FailureReason, detail string, err error) error {
	if detail == "" {
		return fmt.Errorf("%s: %s: %w", pluginName, reason, err)
	}
	return fmt.Errorf("%s: %s (%s): %w", pluginName, reason, detail, err)
}
