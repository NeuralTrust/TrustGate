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

// TestFailOpenExternalAlwaysFailsOpen pins RUN-1792: a third-party
// guardrail failure never refuses the request, whatever the mode or reason.
func TestFailOpenExternalAlwaysFailsOpen(t *testing.T) {
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
				result := FailOpenExternal(ExternalFailure{
					Ctx:    context.Background(),
					Plugin: "some_guardrail",
					Stage:  policy.StagePreRequest,
					Mode:   mode,
					Reason: reason,
					Detail: "some_category",
					Err:    errors.New("dial tcp 10.0.0.1:443: connection refused"),
					Event:  event,
				})
				if result == nil || result.StatusCode != http.StatusOK {
					t.Fatalf("expected pass-through result, got %+v", result)
				}
				if span.Plugin == nil || span.Plugin.Decision != "failed_open" {
					t.Fatalf("span decision = %+v, want failed_open", span.Plugin)
				}
			})
		}
	}
}

func TestFailOpenExternalNilEventAndLoggerAreSafe(t *testing.T) {
	t.Parallel()
	result := FailOpenExternal(ExternalFailure{
		Plugin: "some_guardrail",
		Stage:  policy.StagePreRequest,
		Mode:   policy.ModeEnforce,
		Reason: FailureTransport,
		Err:    errors.New("boom"),
	})
	if result == nil || result.StatusCode != http.StatusOK {
		t.Fatalf("result = %+v, want a pass-through", result)
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
