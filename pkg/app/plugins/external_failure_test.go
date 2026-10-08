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
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

func newTestEvent() (*metrics.EventContext, *trace.Span) {
	span := &trace.Span{Type: trace.SpanPlugin}
	return metrics.NewEventContext(span), span
}

// TestHandleExternalFailureAlwaysFailsOpen pins RUN-1792: a third-party
// guardrail failure never refuses the request, whatever the mode or reason.
func TestHandleExternalFailureAlwaysFailsOpen(t *testing.T) {
	t.Parallel()

	reasons := []FailureReason{
		FailureTransport,
		FailureVerdictIncomplete,
		FailureConfigInvalid,
		FailureDecodeFailed,
	}
	modes := []policy.Mode{policy.ModeEnforce, policy.ModeThrottle, policy.ModeObserve}

	for _, mode := range modes {
		for _, reason := range reasons {
			mode, reason := mode, reason
			t.Run(string(mode)+" "+string(reason), func(t *testing.T) {
				t.Parallel()
				event, span := newTestEvent()
				outcome := HandleExternalFailure(ExternalFailure{
					Ctx:    context.Background(),
					Plugin: "some_guardrail",
					Stage:  policy.StagePreRequest,
					Mode:   mode,
					Reason: reason,
					Detail: "some_category",
					Err:    errors.New("dial tcp 10.0.0.1:443: connection refused"),
					Event:  event,
				})
				if outcome.Err != nil {
					t.Fatalf("expected nil error, got %v", outcome.Err)
				}
				if outcome.Result == nil || outcome.Result.StatusCode != http.StatusOK {
					t.Fatalf("expected pass-through result, got %+v", outcome.Result)
				}
				if outcome.Decision != "failed_open" {
					t.Fatalf("decision = %q, want failed_open", outcome.Decision)
				}
				if span.Plugin == nil || span.Plugin.Decision != "failed_open" {
					t.Fatalf("span decision = %+v, want failed_open", span.Plugin)
				}
			})
		}
	}
}

func TestHandleExternalFailureNilEventAndLoggerAreSafe(t *testing.T) {
	t.Parallel()
	outcome := HandleExternalFailure(ExternalFailure{
		Plugin: "some_guardrail",
		Stage:  policy.StagePreRequest,
		Mode:   policy.ModeEnforce,
		Reason: FailureTransport,
		Err:    errors.New("boom"),
	})
	if outcome.Decision != "failed_open" || outcome.Err != nil {
		t.Fatalf("outcome = %+v, want failed_open with nil error", outcome)
	}
}

func TestWrapExternalStreamFailure(t *testing.T) {
	t.Parallel()
	base := errors.New("boom")

	err := WrapExternalStreamFailure("some_guardrail", FailureTransport, "", base)
	if !errors.Is(err, base) {
		t.Fatalf("wrapped error does not unwrap to base: %v", err)
	}
	if !strings.Contains(err.Error(), "transport") || !strings.Contains(err.Error(), "some_guardrail") {
		t.Fatalf("error = %q, want plugin and reason in text", err.Error())
	}

	withDetail := WrapExternalStreamFailure("some_guardrail", FailureVerdictIncomplete, "hate", base)
	if !strings.Contains(withDetail.Error(), "hate") {
		t.Fatalf("error = %q, want detail in text", withDetail.Error())
	}
}

func TestHandleExternalFailureFailsClosedWhenThePolicyAsks(t *testing.T) {
	t.Parallel()

	for _, reason := range []FailureReason{FailureTransport, FailureVerdictIncomplete, FailureConfigInvalid, FailureDecodeFailed} {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeThrottle} {
			event, span := newTestEvent()
			outcome := HandleExternalFailure(ExternalFailure{
				Ctx:        context.Background(),
				Plugin:     "some_guardrail",
				Stage:      policy.StagePreRequest,
				Mode:       mode,
				Reason:     reason,
				Err:        errors.New("dial tcp 10.0.0.1:443: connection refused"),
				Event:      event,
				FailClosed: true,
			})

			var pluginErr *PluginError
			if !errors.As(outcome.Err, &pluginErr) {
				t.Fatalf("%s/%s: err = %v, want a PluginError", mode, reason, outcome.Err)
			}
			if pluginErr.StatusCode != http.StatusBadGateway || pluginErr.Type != "guardrail_unavailable" {
				t.Fatalf("%s/%s: refusal = %d %s, want 502 guardrail_unavailable", mode, reason, pluginErr.StatusCode, pluginErr.Type)
			}
			if strings.Contains(string(pluginErr.Body), "10.0.0.1") {
				t.Fatalf("%s/%s: body carries the underlying error: %s", mode, reason, pluginErr.Body)
			}
			if outcome.Decision != "failed_closed" || span.Plugin == nil || span.Plugin.Decision != "failed_closed" {
				t.Fatalf("%s/%s: decision = %q, span = %+v, want failed_closed", mode, reason, outcome.Decision, span.Plugin)
			}
		}
	}
}

func TestHandleExternalFailureFailClosedStillPassesObserve(t *testing.T) {
	t.Parallel()

	for _, f := range []ExternalFailure{
		{Mode: policy.ModeObserve, Reason: FailureTransport, FailClosed: true},
		{Mode: policy.ModeObserve, Reason: FailureDecodeFailed, FailClosed: true},
	} {
		f.Ctx, f.Plugin, f.Stage = context.Background(), "some_guardrail", policy.StagePreRequest
		outcome := HandleExternalFailure(f)
		if outcome.Err != nil || outcome.Decision != "failed_open" {
			t.Fatalf("%s/%s: outcome = %+v, want failed_open", f.Mode, f.Reason, outcome)
		}
	}
}
