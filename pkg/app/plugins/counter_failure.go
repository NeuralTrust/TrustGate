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
	"log/slog"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

// CounterFailure is one counter-store (Redis) read or record call's failure,
// ready to be turned into a plugin outcome by HandleCounterFailure. It is the
// rate-limiting family's analogue of ExternalFailure in external_failure.go,
// but for a failure the product owner classified very differently: our own
// infrastructure being unreachable, not a third-party guardrail refusing (or
// failing) to answer.
type CounterFailure struct {
	Ctx    context.Context
	Plugin string
	Stage  policy.Stage
	Mode   policy.Mode
	// Detail names which counter operation failed (e.g. "read", "record"). It
	// is logged here, and is also what the caller's own Data should carry as
	// FailureDetail, next to FailureReason: FailureCounterUnavailable.
	Detail string
	Err    error
	// Logger is optional. rate_limiter, per_tool_rate_limiter and
	// token_rate_limiter carry no logger of their own the way the external
	// guardrails do, so a nil Logger still gets its one Warn line, through the
	// slog default logger, rather than staying silent.
	Logger *slog.Logger
	Event  *metrics.EventContext
}

// HandleCounterFailure applies the rule the product owner set for our own
// infrastructure: a counter-store outage always fails OPEN, in every mode,
// enforce included. The request is never refused for trouble on our side.
// Third-party guardrails fail open on availability failures only
// (HandleExternalFailure): a failure that depends on the request's own content
// is refused in a mode that blocks.
//
// This only decides the outcome, sets the chain-level span decision via
// SetDecisionFromOutcome, and emits the one Warn log the failure gets. The
// caller still owns its own Data: it is responsible for setting
// FailureReason (FailureCounterUnavailable) and FailureDetail (f.Detail), and
// calling setExtras, before or after invoking this — but only when this
// returns a nil error; see below.
//
// A canceled or timed-out ctx is not an outage: it is the caller giving up on
// the request for its own reasons (a client disconnect, an upstream deadline
// unwinding the whole chain), and treating that as "our counter store is
// down" would misreport every request a client abandoned mid-flight as an
// infrastructure incident. So when f.Ctx.Err() != nil this returns (nil,
// f.Err) unchanged: no decision, no extras, no log — the plugin propagates
// the original error exactly as it would have before this helper existed.
// This mirrors the same caller-cancellation guard external guardrails use for
// their own timeout classification (see trustguard's
// `errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil`).
func HandleCounterFailure(f CounterFailure) (*Result, error) {
	if f.Ctx != nil && f.Ctx.Err() != nil {
		return nil, f.Err
	}
	SetDecisionFromOutcome(f.Event, DecisionFailedOpen)
	LogCounterFailure(f, DecisionFailedOpen)
	return &Result{StatusCode: http.StatusOK}, nil
}

// LogCounterFailure emits the one Warn line a counter-store failure gets,
// with the decision the plugin took on it. HandleCounterFailure logs
// DecisionFailedOpen; a plugin that fails closed logs its own decision here so
// both outcomes share one log shape.
func LogCounterFailure(f CounterFailure, decision string) {
	attrs := []any{
		slog.String("plugin", f.Plugin),
		slog.String("stage", string(f.Stage)),
		slog.String("mode", string(f.Mode)),
		slog.String("reason", string(FailureCounterUnavailable)),
		slog.String("decision", decision),
	}
	if f.Detail != "" {
		attrs = append(attrs, slog.String("detail", f.Detail))
	}
	if f.Err != nil {
		attrs = append(attrs, slog.Any("error", f.Err))
	}
	logger := f.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if f.Ctx != nil {
		logger.WarnContext(f.Ctx, "counter store call failed", attrs...)
		return
	}
	logger.Warn("counter store call failed", attrs...)
}
