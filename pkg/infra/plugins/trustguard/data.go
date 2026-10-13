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
	"encoding/json"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

type GuardRequest struct {
	OriginalRequest *requestmeta.OriginalRequest `json:"original_request,omitempty"`
	Payload         json.RawMessage              `json:"payload"`
	Direction       string                       `json:"direction"`
	Protocol        string                       `json:"protocol"`
	GatewayID       string                       `json:"gateway_id"`
	SessionID       string                       `json:"session_id"`
	ConsumerID      string                       `json:"consumer_id"`
	Attributes      GuardAttributes              `json:"attributes"`
}

type GuardUser struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
}

// GuardPayload is the minimal LLM evaluate body used for response-direction
// inspect (assistant text). Request-direction LLM evaluates use messages[].
type GuardPayload struct {
	Input       string            `json:"input"`
	Attachments []GuardAttachment `json:"attachments,omitempty"`
}

type GuardAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Data        string `json:"data,omitempty"`
	URL         string `json:"url,omitempty"`
}

type GuardAttributes struct {
	ContentType string         `json:"content_type"`
	Model       GuardModel     `json:"model"`
	User        *GuardUser     `json:"user,omitempty"`
	Consumer    *GuardConsumer `json:"consumer,omitempty"`
	Stream      *GuardStream   `json:"stream,omitempty"`
}

// GuardConsumer names the application a request came from. TrustGuard stores
// the name with the event only when it is sent here, and the console's Activity
// otherwise has the id alone for a consumer it cannot look up — the MCP Store's,
// which is synthetic, and one deleted since.
type GuardConsumer struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// GuardStream correlates the evaluate calls of a single streamed response so
// the engine can make side effects idempotent. It is not needed for detection:
// the cumulative payload already carries the context. It hangs off attributes
// rather than the request root because the engine's strict decoder rejects
// unknown top-level fields but leaves attributes free-form.
type GuardStream struct {
	// ID is derived from the gateway trace id plus the response leg, so it is
	// distinct from SessionID, which spans the whole conversation.
	ID  string `json:"id"`
	Seq int    `json:"seq"`
	// Final marks the last evaluate of the stream and is the engine's cue to
	// settle whatever it deferred across the earlier blocks.
	Final bool `json:"final"`
	// Block is the 1-based position of this evaluate among the evaluates the
	// plugin actually sent for the stream. Seq counts every segment the stream
	// guard produced, including those this plugin skipped (empty text, a retired
	// stream), so a response whose first segments were skipped would never put a
	// seq 1 on the wire. The engine reads Block to decide which calls of a
	// stream own a plan charge; omitted, it falls back to Seq. An engine that
	// predates the field ignores it, since attributes are free-form.
	Block int `json:"block,omitempty"`
	// Truncated says the accumulation cap swapped the payload from a full
	// prefix to a tail window, so the engine can tell the two apart instead of
	// reading a window as the whole response.
	Truncated bool `json:"truncated,omitempty"`
}

type GuardModel struct {
	Name     string `json:"name,omitempty"`
	Provider string `json:"provider,omitempty"`
}

type GuardResponse struct {
	Status             string         `json:"status"`
	TransformedPayload map[string]any `json:"transformed_payload"`
	Findings           []GuardFinding `json:"findings"`
	TraceID            string         `json:"trace_id"`
	RequestID          string         `json:"request_id"`
}

// GuardFindingSource identifies who produced a guard finding.
type GuardFindingSource struct {
	Kind         string `json:"kind,omitempty"`
	Plugin       string `json:"plugin,omitempty"`
	DetectorID   string `json:"detector_id,omitempty"`
	DetectorName string `json:"detector_name,omitempty"`
	PolicyID     string `json:"policy_id,omitempty"`
	GateName     string `json:"gate_name,omitempty"`
}

// GuardFindingSignal is the detection signal when a plugin or gate matched.
type GuardFindingSignal struct {
	Type       string  `json:"type,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// GuardFindingOutcome is the enforcement action applied to a real detection.
type GuardFindingOutcome struct {
	Action string `json:"action,omitempty"`
}

// GuardFinding is one TrustGuard finding in the guard wire contract.
type GuardFinding struct {
	Source   *GuardFindingSource  `json:"source,omitempty"`
	Signal   *GuardFindingSignal  `json:"signal,omitempty"`
	Outcome  *GuardFindingOutcome `json:"outcome,omitempty"`
	Evidence map[string]any       `json:"evidence,omitempty"`
}

type guardData struct {
	Direction     string         `json:"direction,omitempty"`
	Status        string         `json:"status,omitempty"`
	Decision      string         `json:"decision,omitempty"`
	TraceID       string         `json:"trace_id,omitempty"`
	RequestID     string         `json:"request_id,omitempty"`
	FindingsCount int            `json:"findings_count,omitempty"`
	Findings      []GuardFinding `json:"findings,omitempty"`
	FailedOpen    bool           `json:"failed_open,omitempty"`
	// FailedClosed is set with decision failed_closed: the guard could not
	// inspect the request's own content and a mode that blocks refused it.
	FailedClosed  bool   `json:"failed_closed,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
	// FailureClass is availability or input (appplugins.ClassOf): whether the
	// failure was TrustGuard's or the request's own content.
	FailureClass string `json:"failure_class,omitempty"`
	// FailureDetail refines FailureReason when it is the shared verdict_incomplete
	// (attachment_not_fetched). It is absent for every other reason, which this
	// plugin names in its own vocabulary.
	FailureDetail  string `json:"failure_detail,omitempty"`
	Degraded       bool   `json:"degraded,omitempty"`
	DegradedReason string `json:"degraded_reason,omitempty"`
	// Skipped marks a leg the plugin decided not to inspect at all. Without
	// it, "inspected and clean" and "never looked" produce an identical
	// event, which is what let response coverage lapse unnoticed. Both fields
	// are omitempty, so events that did inspect are unchanged.
	Skipped    bool   `json:"skipped,omitempty"`
	SkipReason string `json:"skip_reason,omitempty"`
	// AttachmentsNotInspected counts the attachments of the request that were
	// not sent because TrustGuard cannot resolve them (a file_id, a gs:// URI,
	// data that is not base64). The text beside them was inspected; the
	// attachments were not.
	AttachmentsNotInspected int `json:"attachments_not_inspected,omitempty"`
	// AttachmentsNotFetched counts the attachments sent as a URL that TrustGuard
	// could not fetch (a Gemini Files URI needs the caller's key, or the fetch
	// failed), so the text was evaluated without them. They are also in
	// AttachmentsNotInspected.
	AttachmentsNotFetched int `json:"attachments_not_fetched,omitempty"`
	// Streaming carries the per-stream aggregate for a response inspected
	// block by block. It is a pointer so the buffered path, which has nothing
	// to say about streaming, keeps emitting an identical event.
	Streaming *streamData `json:"streaming,omitempty"`
}

// streamData is the per-stream aggregate of one streamed response leg. The
// whole block is written once, at the end: Span.SetExtras overwrites rather
// than merges, so a per-block write would destroy the previous one. Its fields
// carry no omitempty on purpose — once the block is present, a zero is an
// answer ("no cut", "no degradation") and dropping it would make the absent
// key ambiguous with a leg that never reported.
type streamData struct {
	Enabled             bool   `json:"enabled"`
	StreamID            string `json:"stream_id"`
	EvalsTotal          int    `json:"evals_total"`
	CutAtEval           int    `json:"cut_at_eval"`
	CutOffsetChars      int    `json:"cut_offset_chars"`
	FinalPass           bool   `json:"final_pass"`
	GuardCalls          int    `json:"guard_calls"`
	GuardLatencyMsTotal int64  `json:"guard_latency_ms_total"`
	GuardLatencyMsMax   int64  `json:"guard_latency_ms_max"`
	AddedLatencyMs      int64  `json:"added_latency_ms"`
	DegradedReason      string `json:"degraded_reason"`
	FallbackReason      string `json:"fallback_reason"`
	// Findings is the one exception to the rule above: an absent key and an
	// empty list both say the stream reported nothing, so there is no zero to
	// preserve, and omitting it keeps a stream with no findings emitting the
	// event it emitted before this field existed.
	//
	// It holds fingerprints and never a finding's own fields. evidence is
	// free-form and carries flagged response text, so a findings list here
	// would be a second route for it onto the span; the fingerprint is a digest
	// over a detector name, a signal label and an action, and nothing about the
	// response can be recovered from it.
	Findings []string `json:"findings,omitempty"`
}

// Stream outcomes for trustguard_stream_evals_total. They answer "what happened
// to the response" in one label: cut by a verdict, released after the guard
// gave up on a block, released after the block loop retired, never inspected at
// all, or inspected clean.
const (
	streamOutcomeBlocked = "blocked"
	// streamOutcomeFailedOpen is a stream on which the guard failed and at
	// least one block went through uninspected; it ranks just below a cut.
	streamOutcomeFailedOpen = "failed_open"
	streamOutcomeDegraded   = "degraded"
	streamOutcomeFallback   = "fallback"
	streamOutcomeSkipped    = "skipped"
	streamOutcomeAllowed    = "allowed"
)

// streamOutcome folds the per-stream aggregate into the guardData written once
// at the end of a streamed response leg.
//
// evals_total of zero is a skip, not a clean pass: the policy asked for
// per-block inspection and got no block, which is the one case where an event
// with no findings would otherwise read as "inspected and clean".
func streamOutcome(streamID string, r appplugins.StreamReport) guardData {
	data := guardData{
		Direction: directionOutput,
		Decision:  decisionAllowed,
		Streaming: &streamData{
			Enabled:             true,
			StreamID:            streamID,
			EvalsTotal:          r.Evals,
			CutAtEval:           r.CutAtEval,
			CutOffsetChars:      r.CutOffsetChars,
			FinalPass:           r.FinalPass,
			GuardCalls:          r.GuardCalls,
			GuardLatencyMsTotal: r.GuardLatency.Milliseconds(),
			GuardLatencyMsMax:   r.GuardLatencyMax.Milliseconds(),
			AddedLatencyMs:      r.AddedLatency.Milliseconds(),
			DegradedReason:      r.DegradedReason,
			FallbackReason:      r.FallbackReason,
		},
	}
	if r.DegradedReason != "" {
		data.Degraded = true
		data.DegradedReason = r.DegradedReason
	}
	switch {
	case r.CutAtEval > 0:
		data.Decision = decisionBlocked
		if r.CutOnFailure {
			data.FailureReason, data.FailureClass = failureOfCut(r)
			data.Decision = pluginutil.StreamCutDecision(r, decisionBlocked)
			data.FailedClosed = data.Decision == decisionFailedClosed
			if appplugins.IsMaskOverFinding(r.FailureDetail) {
				data.Degraded = true
				data.DegradedReason = transformReasonOf(r.FailureDetail)
			}
		}
	case r.Evals == 0:
		data.Skipped = true
		data.SkipReason = skipReasonProviderNotStreaming
	case r.MaskedEvals > 0:
		// The guard applies a mask or cuts, so with no cut every mask this
		// entry produced reached the client, as a buffered mask does.
		data.Decision = decisionTransformed
	}
	return data
}

// streamOutcomeLabel is the metric dimension for one streamed response. A cut
// dominates, then the fallback that retired the loop, then the degrade that
// released a single block: the labels are ordered by how much of the response
// went uninspected, so the most serious answer is the one that gets counted.
func streamOutcomeLabel(r appplugins.StreamReport) string {
	switch {
	case r.CutAtEval > 0:
		return streamOutcomeBlocked
	case r.FallbackReason == fallbackReasonSegmentationUnavail,
		r.FallbackReason == fallbackReasonClientDisconnected:
		return streamOutcomeFallback
	case r.DegradedReason == degradedReasonGuardTimeout,
		r.DegradedReason == degradedReasonGuardError,
		r.DegradedReason == degradedReasonAccumulationCap:
		return streamOutcomeDegraded
	case r.Evals == 0:
		return streamOutcomeSkipped
	default:
		return streamOutcomeAllowed
	}
}

func setExtras(event *metrics.EventContext, data guardData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

func recordGuardOutcome(event *metrics.EventContext, data guardData) {
	setExtras(event, data)
	if scoreLabelWorthy(data.Decision) {
		if label, score, ok := primaryFinding(data.Findings); ok {
			event.SetScore(score, label)
		}
	}
	appplugins.SetDecisionFromOutcome(event, data.Decision)
}

// scoreLabelWorthy reports whether a guard decision represents an actual
// detection worth surfacing in the Security Engine breakdown. Pass-through
// outcomes (allowed, failed_open) must not emit a score label.
func scoreLabelWorthy(decision string) bool {
	switch decision {
	case decisionBlocked, decisionReported, decisionTransformed:
		return true
	default:
		return false
	}
}

// primaryFinding selects the finding that best represents the guard decision for
// the Security Engine metric: the enforced detection with the highest
// confidence, falling back to the highest-confidence signal when nothing was
// enforced. It returns ok=false when no finding carries a usable signal type.
func primaryFinding(findings []GuardFinding) (label string, score float64, ok bool) {
	chosen := selectPrimaryFinding(findings)
	if chosen == nil || chosen.Signal == nil {
		return "", 0, false
	}
	return chosen.Signal.Type, chosen.Signal.Confidence, true
}

// selectPrimaryFinding returns the enforced finding with the highest
// confidence, or the highest-confidence signal when nothing was enforced.
func selectPrimaryFinding(findings []GuardFinding) *GuardFinding {
	var enforced, any *GuardFinding
	for i := range findings {
		f := &findings[i]
		if f.Signal == nil || f.Signal.Type == "" {
			continue
		}
		if any == nil || f.Signal.Confidence > any.Signal.Confidence {
			any = f
		}
		if f.Outcome != nil && f.Outcome.Action != "" {
			if enforced == nil || f.Signal.Confidence > enforced.Signal.Confidence {
				enforced = f
			}
		}
	}
	if enforced != nil {
		return enforced
	}
	return any
}
