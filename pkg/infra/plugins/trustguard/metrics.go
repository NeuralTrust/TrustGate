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

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	failureReasonUnauthorized = "unauthorized"
	failureReasonTransport    = "transport"
	failureReasonTimeout      = "timeout"
	// failureReasonCredentialsMissing and failureReasonBaseURLMissing are a pod
	// started without TRUSTGUARD_CLIENT_ID/SECRET or TRUSTGUARD_BASE_URL: no
	// call is made at all.
	failureReasonCredentialsMissing      = "credentials_missing"
	failureReasonBaseURLMissing          = "base_url_missing"
	failureReasonEntitlementsUnavailable = "entitlements_unavailable"
	failureReasonConfigInvalid           = "config_invalid"
	failureReasonGatewayIDMissing        = "gateway_id_missing"
	// failureReasonProviderMissing is an LLM request with no provider set, so
	// the leg is not decoded and no evaluate call is made.
	failureReasonProviderMissing   = "provider_missing"
	failureReasonPayloadUnreadable = "payload_unreadable"
	// failureReasonPayloadTooLarge is TrustGuard refusing the body for its size
	// (HTTP 413): what the request carries, not the engine being unavailable.
	failureReasonPayloadTooLarge = "payload_too_large"
	// failureReasonStreamBlockTooLarge is a streamed block above the one evaluate
	// this plugin sends for it (the stream window): refused before any call as the
	// response's own size, with the detail chunk_limit. It is distinct from
	// payload_too_large, which is TrustGuard's 413 or the 8 MiB buffered limit.
	failureReasonStreamBlockTooLarge = "stream_block_too_large"
	// failureReasonAttachmentRejected is TrustGuard answering 400 "invalid
	// attachment": it could not fetch or decode an attachment it was sent.
	failureReasonAttachmentRejected = "attachment_rejected"
	// failureReasonResponseTooLarge is an answer above what the client reads:
	// the mask echoes the request's text, so the request chose its size.
	failureReasonResponseTooLarge = "response_too_large"
	// failureReasonTransformFailed is TrustGuard asking for a mask this plugin
	// could not write back; degraded_reason on the span says which step failed.
	failureReasonTransformFailed = "transform_failed"
	// failureReasonVerdictIncomplete is an evaluation that ran without part of
	// what the request carried: an attachment sent as a URL that TrustGuard could
	// not fetch. The shared reason of the same name, with the detail
	// attachment_not_fetched; availability.
	failureReasonVerdictIncomplete = "verdict_incomplete"
)

var (
	instrumentsOnce        sync.Once
	evaluateFailures       metric.Int64Counter
	streamEvals            metric.Int64Counter
	streamResponses        metric.Int64Counter
	streamGuardCalls       metric.Int64Histogram
	streamAddedLatency     metric.Int64Histogram
	agentSecurityEvaluates metric.Int64Counter
	agentSecurityFailures  metric.Int64Counter
	agentSecurityLatency   metric.Int64Histogram
)

// Outcomes of agentsecurity_evaluate_total: answered, failed, never sent
// because AgentSecurity has no a2a, or dropped because too many copies were waiting.
const (
	agentSecurityOutcomeOK      = "ok"
	agentSecurityOutcomeFailed  = "failed"
	agentSecurityOutcomeSkipped = "skipped"
	agentSecurityOutcomeDropped = "dropped"
	// Skips by gateway: AgentSecurity does not know it or cannot pick its integration.
	agentSecurityOutcomeUnknownGateway   = "skipped_unknown_gateway"
	agentSecurityOutcomeAmbiguousGateway = "skipped_ambiguous_gateway"
	// Skipped during the backoff that follows a failed token request.
	agentSecurityOutcomeTokenBackoff = "skipped_token_unavailable"
)

func initInstruments() {
	instrumentsOnce.Do(func() {
		meter := otel.Meter("trustgate/trustguard")
		if c, err := meter.Int64Counter(
			"trustguard_evaluate_failures_total",
			metric.WithDescription("TrustGuard /v1/evaluate call failures by reason"),
		); err == nil {
			evaluateFailures = c
		}
		if c, err := meter.Int64Counter(
			"trustguard_stream_evals_total",
			metric.WithDescription("Per-block TrustGuard evaluations of streamed responses by stream outcome"),
		); err == nil {
			streamEvals = c
		}
		if c, err := meter.Int64Counter(
			"trustguard_stream_responses_total",
			metric.WithDescription("Streamed responses inspected block by block, by stream outcome"),
		); err == nil {
			streamResponses = c
		}
		if h, err := meter.Int64Histogram(
			"trustguard_stream_guard_calls_per_response",
			metric.WithDescription("TrustGuard evaluate calls issued per streamed response"),
		); err == nil {
			streamGuardCalls = h
		}
		if h, err := meter.Int64Histogram(
			"trustguard_stream_added_latency_ms",
			metric.WithUnit("ms"),
			metric.WithDescription(
				"Sum over a streamed response of how long each held block waited before its first event reached the client",
			),
		); err == nil {
			streamAddedLatency = h
		}
		if c, err := meter.Int64Counter(
			"agentsecurity_evaluate_total",
			metric.WithDescription("Evaluations copied to AgentSecurity by outcome"),
		); err == nil {
			agentSecurityEvaluates = c
		}
		if c, err := meter.Int64Counter(
			"agentsecurity_evaluate_failures_total",
			metric.WithDescription("AgentSecurity evaluate copies that failed, by reason"),
		); err == nil {
			agentSecurityFailures = c
		}
		if h, err := meter.Int64Histogram(
			"agentsecurity_evaluate_latency_ms",
			metric.WithUnit("ms"),
			metric.WithDescription("Duration of the AgentSecurity evaluate copy, token included, by outcome"),
		); err == nil {
			agentSecurityLatency = h
		}
	})
}

func recordAgentSecurityOutcome(ctx context.Context, outcome string) {
	initInstruments()
	if agentSecurityEvaluates == nil {
		return
	}
	agentSecurityEvaluates.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}

func recordAgentSecurityCall(ctx context.Context, elapsed time.Duration, err error) {
	outcome := agentSecurityOutcomeOK
	if err != nil {
		outcome = agentSecurityOutcomeFailed
	}
	recordAgentSecurityOutcome(ctx, outcome)
	if agentSecurityLatency != nil {
		agentSecurityLatency.Record(ctx, elapsed.Milliseconds(), metric.WithAttributes(
			attribute.String("outcome", outcome),
		))
	}
	if err != nil && agentSecurityFailures != nil {
		agentSecurityFailures.Add(ctx, 1, metric.WithAttributes(
			attribute.String("reason", agentSecurityFailureReason(err)),
		))
	}
}

// agentSecurityFailureReason keeps a 400 apart from every other refusal: it is AgentSecurity
// rejecting the body this plugin built, which is the contract breaking.
func agentSecurityFailureReason(err error) string {
	var status *agentSecurityStatusError
	var rejected *authRejectedError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return failureReasonTimeout
	case errors.As(err, &status):
		switch status.status {
		case http.StatusBadRequest:
			return "bad_request"
		case http.StatusUnauthorized, http.StatusForbidden:
			return failureReasonUnauthorized
		case http.StatusTooManyRequests:
			return "rate_limited"
		default:
			return "status_" + strconv.Itoa(status.status)
		}
	case errors.As(err, &rejected):
		return failureReasonUnauthorized
	default:
		return failureReasonTransport
	}
}

func recordEvaluateFailure(ctx context.Context, reason string) {
	initInstruments()
	if evaluateFailures == nil {
		return
	}
	evaluateFailures.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}

// recordStreamEvals publishes one streamed response, from the entry the
// executor designated to speak for the whole stream. Every instrument here is
// keyed on the response rather than on the policy, so recording it once per
// entry would count a single response once per streaming policy in the chain.
//
// The response counter is not derivable from the eval counter: skipped is
// defined as no evals at all, so its share of trustguard_stream_evals_total is
// zero by construction and only a count of responses can answer how many
// streams were never inspected.
func recordStreamEvals(ctx context.Context, r appplugins.StreamReport, failedOpen bool) {
	initInstruments()
	label := streamOutcomeLabel(r)
	if failedOpen && label != streamOutcomeBlocked {
		label = streamOutcomeFailedOpen
	}
	outcome := metric.WithAttributes(attribute.String("outcome", label))
	if streamEvals != nil {
		streamEvals.Add(ctx, int64(r.Evals), outcome)
	}
	if streamResponses != nil {
		streamResponses.Add(ctx, 1, outcome)
	}
	if streamGuardCalls != nil {
		streamGuardCalls.Record(ctx, int64(r.GuardCalls))
	}
	if streamAddedLatency != nil {
		streamAddedLatency.Record(ctx, r.AddedLatency.Milliseconds())
	}
}
