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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

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
	// FailureDecodeFailed is a request body that a chat route promised and the
	// adapters cannot decode, before the guardrail ever saw it. The guardrail
	// was never consulted, so there was nothing for it to say. A response body
	// that cannot be decoded is the upstream's and is skipped, not failed, and a
	// route with no chat decoder is config_invalid (unsupported_format).
	FailureDecodeFailed FailureReason = "decode_failed"
	// FailureCounterUnavailable is TrustGate's own counter store (Redis)
	// failing a read or a write: rate_limiter, per_tool_rate_limiter and
	// token_rate_limiter all share this one reason. It is handled by
	// HandleCounterFailure in counter_failure.go, not by HandleExternalFailure;
	// token_rate_limiter with partition key fails closed there on a read in a
	// blocking mode.
	FailureCounterUnavailable FailureReason = "counter_unavailable"
	// FailureInputTooLarge is a guardrail that could not inspect this request's
	// own content: the provider refused it for what it carries (a 4xx client
	// error, a 413). The class is the input's, not the provider's.
	FailureInputTooLarge FailureReason = "input_too_large"
)

// FailureClass says what a failure depends on, which is what decides whether
// traffic may go through uninspected. An availability failure is the
// provider, the network or the deployment: nothing about the request caused
// it, so the request continues. An input failure is the request's own content:
// a client can steer it, so letting it through would hand any caller a way
// round the guardrail, and Enforce refuses it.
type FailureClass string

const (
	FailureClassAvailability FailureClass = "availability"
	FailureClassInput        FailureClass = "input"
)

// The details a (reason, detail) pair is classified on. They are the values
// plugins already record as failure_detail, so naming them here does not change
// the wire.
const (
	DetailFilterNotExecuted       = "filter_not_executed"
	DetailFilterNotInTemplate     = "filter_not_in_template"
	DetailFilterStateUnspecified  = "filter_state_unspecified"
	DetailInvocationPartial       = "invocation_partial"
	DetailInterventionUnparsed    = "intervention_unparsed"
	DetailAnonymizeNoOutput       = "anonymize_no_output"
	DetailAnonymizeUnsupportedFmt = "anonymize_unsupported_format"
	DetailAnonymizeEncodeFailed   = "anonymize_encode_failed"
	DetailProviderRejectedInput   = "provider_rejected_input"
	DetailPayloadTooLarge         = "payload_too_large"
	DetailAnswerTooLarge          = "answer_too_large"
	DetailThrottled               = "throttled"
	DetailUnsupportedFormat       = "unsupported_format"
	DetailProviderConfigRejected  = "provider_config_rejected"
	DetailCoveragePartial         = "coverage_partial"
	// DetailProviderQuotaExhausted is a provider quota that is configuration, not
	// load: an account out of credit or at its billing limit. Nothing a request
	// does changes it, so it is config_invalid and never the throttled detail,
	// whatever the number of chunks.
	DetailProviderQuotaExhausted = "provider_quota_exhausted"
	// DetailAttachmentNotFetched is an attachment sent as a URL that the guard
	// could not fetch, so the rest of the request was evaluated without it. It
	// is availability (a CDN that is down must not block legitimate traffic) and
	// is recorded as a failure so it alerts instead of passing as a clean
	// evaluation.
	DetailAttachmentNotFetched = "attachment_not_fetched"
	// DetailChunkLimit is a content that splits into more chunks than the
	// guardrail evaluates, or a streamed block above the one call TrustGuard
	// accepts. It is refused before any call is made.
	DetailChunkLimit = "chunk_limit"
	// DetailChunkBudget is the evaluation's time budget used up by the request's
	// own size: a chunk that was never started, or was started and cut by the
	// budget, after waiting behind the request's own earlier chunks. Bedrock
	// reads it before any call, from an estimate: a request whose spacing and
	// calls cannot fit the budget is refused. Once Bedrock admits a request, a
	// later chunk that the budget cuts is availability, not this.
	DetailChunkBudget = "chunk_budget"
	// DetailThrottledOversize is a provider rate limit answered to a chunk that
	// was dispatched after the first round, behind the request's own earlier
	// calls: they can have caused it. A throttle on a chunk of the first round
	// is other traffic and stays availability.
	DetailThrottledOversize = "throttled_oversize"
)

// IsMaskOverFinding reports whether a failure detail is a mask that could not
// be applied. The provider confirmed a finding and the plugin cannot write the
// masked text back, so what is refused is a finding, not a missing inspection.
func IsMaskOverFinding(detail string) bool {
	switch detail {
	case DetailAnonymizeNoOutput, DetailAnonymizeUnsupportedFmt, DetailAnonymizeEncodeFailed:
		return true
	}
	return false
}

// ClassOf is the one classification of an external guardrail failure. Plugins
// only map what a provider answered to a (reason, detail) pair; they never
// decide whether the traffic goes through. A pair this table does not name is
// availability, so a new reason cannot start refusing traffic by omission.
//
// decode_failed is input: a chat body the adapters cannot decode is the
// client's, and one the upstream accepts would otherwise skip the guardrail. A
// provider or format the gateway does not support at all, and a route that has
// no chat decoder (images, audio, files), is not the body's fault but a
// configuration gap, and is config_invalid (unsupported_format).
// filter_not_in_template stays availability: it is the customer's template, not
// anything the request did.
func ClassOf(reason FailureReason, detail string) FailureClass {
	switch reason {
	case FailureDecodeFailed, FailureInputTooLarge:
		return FailureClassInput
	case FailureVerdictIncomplete:
		switch detail {
		case DetailFilterNotExecuted, DetailInterventionUnparsed, DetailCoveragePartial:
			return FailureClassInput
		}
		if IsMaskOverFinding(detail) {
			return FailureClassInput
		}
	}
	return FailureClassAvailability
}

// DecisionFailedOpen is the decision recorded when a guardrail could not give
// a verdict and the traffic was let through. The buffered legs and the stream
// leg share it.
const DecisionFailedOpen = "failed_open"

// DecisionFailedClosed is the decision recorded when a policy could not do its
// work and the traffic was refused: a guardrail that could not inspect the
// request's own content in a mode that blocks, or a stream cut that the guard
// resolved on a failed call of a rewriter that asked for fail_closed
// (regex_replace).
const DecisionFailedClosed = "failed_closed"

// DecisionBlocked is the decision recorded when a finding is refused, which
// includes a mask over a confirmed finding that cannot be applied.
const DecisionBlocked = "blocked"

// TypeGuardrailInputUninspectable is the error type of the 403 a guardrail
// answers when it could not inspect the content of the request itself.
const TypeGuardrailInputUninspectable = "guardrail_input_uninspectable"

// DefaultUninspectableMessage is the refusal text when the policy configures no
// message of its own. It never carries the provider's error, which can hold
// endpoint hostnames or vendor text.
const DefaultUninspectableMessage = "request blocked: the policy could not inspect this content"

// ExternalFailure is one third-party guardrail call's failure, ready to be
// handed to HandleExternalFailure.
type ExternalFailure struct {
	Ctx    context.Context
	Plugin string
	Stage  policy.Stage
	Mode   policy.Mode
	Reason FailureReason
	// Detail names the reason within Reason (a skipped filter, an anonymize
	// that could not be applied). The class is read from it, and it is named in
	// the Warn log. This helper does not write it onto any Data struct: the
	// caller decides where its own Data carries it.
	Detail string
	// Message is the policy's configured block message, used for the refusal of
	// an input failure. Empty means DefaultUninspectableMessage.
	Message string
	// Finding is the plugin's normal block error, set only for a mask over a
	// confirmed finding: refusing it is a block of that finding, so it is
	// answered as the plugin answers a block.
	Finding *PluginError
	Err     error
	Logger  *slog.Logger
	Event   *metrics.EventContext
}

// ExternalFailureOutcome is HandleExternalFailure's answer. Decision and Class
// are what the caller's own Data records (decision, failure_class); Result and
// Err are exactly what the plugin's Execute returns, and exactly one is set.
type ExternalFailureOutcome struct {
	Decision string
	Class    FailureClass
	Result   *Result
	Err      *PluginError
}

// HandleExternalFailure applies the one rule every external guardrail follows
// on a failure of its buffered (non-streamed) leg. The class is ClassOf's, and
// the mode decides what it costs:
//
//   - availability, in any mode: the request continues, failed_open;
//   - input in observe: the request continues, failed_open, since observe never
//     blocks;
//   - input in a blocking mode: the request is refused with a 403
//     guardrail_input_uninspectable, failed_closed;
//   - a mask over a finding in a blocking mode: the finding is refused with the
//     plugin's own block error, blocked.
//
// There is no policy setting that changes this.
//
// This only decides the outcome, sets the chain-level span decision via
// SetDecisionFromOutcome, and emits the one Warn log the failure gets. The
// caller still owns its own Data: it records Decision, the failure_reason and
// failure_detail it names, and Class as failure_class.
func HandleExternalFailure(f ExternalFailure) ExternalFailureOutcome {
	class := ClassOf(f.Reason, f.Detail)
	outcome := ExternalFailureOutcome{
		Decision: DecisionFailedOpen,
		Class:    class,
		Result:   &Result{StatusCode: http.StatusOK},
	}
	if class == FailureClassInput && Blocks(f.Mode) {
		outcome.Result = nil
		if f.Finding != nil && IsMaskOverFinding(f.Detail) {
			outcome.Decision = DecisionBlocked
			outcome.Err = f.Finding
		} else {
			outcome.Decision = DecisionFailedClosed
			outcome.Err = UninspectableError(f.Message)
		}
	}
	SetDecisionFromOutcome(f.Event, outcome.Decision)
	logExternalFailure(f, outcome.Decision)
	return outcome
}

// UninspectableError is the 403 a guardrail answers when it could not inspect
// the content of the request. It is a refusal of the content, not a gateway
// fault, so it is not a 502 that invites a retry.
func UninspectableError(message string) *PluginError {
	msg := strings.TrimSpace(message)
	if msg == "" {
		msg = DefaultUninspectableMessage
	}
	return &PluginError{
		StatusCode: http.StatusForbidden,
		Type:       TypeGuardrailInputUninspectable,
		Message:    msg,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       uninspectableBody(msg),
	}
}

func uninspectableBody(message string) []byte {
	body := struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}{}
	body.Error.Type = TypeGuardrailInputUninspectable
	body.Error.Message = message
	raw, err := json.Marshal(body)
	if err != nil {
		return []byte(fmt.Sprintf(`{"error":{"type":%q}}`, TypeGuardrailInputUninspectable))
	}
	return raw
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
// It is the availability path of the stream: the error is absorbed per entry by
// the executor and the held text is released, as a failed call that says
// nothing about the content. A failure that depends on the content goes through
// ExternalStreamOutcome, which decides between this and a cut. The guard also
// already logs the returned error itself (headFailure/blockFailure), so this
// does not log again.
//
// The error is typed (*ExternalStreamFailure) so the executor can read the
// reason, detail and class off it with errors.As and carry them to the closing
// segment, where the entry's span is written once. Its text is unchanged.
func WrapExternalStreamFailure(pluginName string, reason FailureReason, detail string, err error) error {
	return newExternalStreamFailure(pluginName, reason, detail, err)
}

func newExternalStreamFailure(pluginName string, reason FailureReason, detail string, err error) *ExternalStreamFailure {
	return &ExternalStreamFailure{Plugin: pluginName, Reason: reason, Detail: detail, Class: ClassOf(reason, detail), Err: err}
}

// ExternalStreamOutcome is the stream twin of HandleExternalFailure: the only
// place a streamed block's failure becomes an outcome. It returns either a
// verdict (the stream is cut) or the typed error (the block is released).
//
//   - availability, any mode: the typed error, absorbed as failed_open;
//   - input in observe: the typed error, absorbed as failed_open, and not
//     counted toward retiring the entry, so a padded stream cannot switch off
//     its own inspection. When block carries the fingerprints of a confirmed
//     finding (a mask over it), the finding is still reported: the verdict is a
//     non-blocking one that keeps the failure as Incomplete;
//   - input in a blocking mode: a Block verdict carrying the failure, which the
//     executor records as failed_closed on the entry that authored the cut;
//   - a mask over a finding in a blocking mode: the same cut, recorded as
//     blocked and degraded.
//
// block is the verdict the plugin answers a block with (its Type and Message);
// nil gives the uninspectable refusal.
func ExternalStreamOutcome(
	plugin string,
	mode policy.Mode,
	reason FailureReason,
	detail string,
	block *SegmentVerdict,
	err error,
) (*SegmentVerdict, error) {
	failure := newExternalStreamFailure(plugin, reason, detail, err)
	if failure.Class != FailureClassInput {
		return nil, failure
	}
	if !Blocks(mode) {
		if block != nil {
			return &SegmentVerdict{Fingerprints: block.Fingerprints, Incomplete: failure}, nil
		}
		return nil, failure
	}
	verdict := SegmentVerdict{Block: true, Type: TypeGuardrailInputUninspectable, Message: DefaultUninspectableMessage}
	if block != nil {
		verdict = *block
		verdict.Block = true
	}
	verdict.Failure = failure
	return &verdict, nil
}

// ExternalStreamFailure is one external guardrail's failure on a streamed
// block, as WrapExternalStreamFailure builds it. Reason, Detail and Class are
// the same vocabulary HandleExternalFailure records on the buffered leg.
type ExternalStreamFailure struct {
	Plugin string
	Reason FailureReason
	Detail string
	Class  FailureClass
	Err    error
}

// Error keeps the text the stream guard has always logged: plugin, reason,
// the detail in parentheses when there is one, then the underlying error.
func (f *ExternalStreamFailure) Error() string {
	if f.Detail == "" {
		return fmt.Sprintf("%s: %s: %v", f.Plugin, f.Reason, f.Err)
	}
	return fmt.Sprintf("%s: %s (%s): %v", f.Plugin, f.Reason, f.Detail, f.Err)
}

func (f *ExternalStreamFailure) Unwrap() error { return f.Err }
