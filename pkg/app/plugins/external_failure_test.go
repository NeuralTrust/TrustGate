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

func TestHandleExternalFailure(t *testing.T) {
	t.Parallel()

	secretErr := errors.New("dial tcp 10.0.0.1:443: connection refused")

	tests := []struct {
		name       string
		mode       policy.Mode
		reason     FailureReason
		wantResult bool
		wantErr    bool
		wantStatus int
	}{
		{name: "enforce transport fails closed", mode: policy.ModeEnforce, reason: FailureTransport, wantErr: true, wantStatus: http.StatusBadGateway},
		{name: "observe transport fails open", mode: policy.ModeObserve, reason: FailureTransport, wantResult: true},
		{name: "enforce verdict_incomplete fails closed", mode: policy.ModeEnforce, reason: FailureVerdictIncomplete, wantErr: true, wantStatus: http.StatusBadGateway},
		{name: "observe verdict_incomplete fails open", mode: policy.ModeObserve, reason: FailureVerdictIncomplete, wantResult: true},
		{name: "enforce config_invalid fails closed", mode: policy.ModeEnforce, reason: FailureConfigInvalid, wantErr: true, wantStatus: http.StatusBadGateway},
		{name: "observe config_invalid fails open", mode: policy.ModeObserve, reason: FailureConfigInvalid, wantResult: true},
		{name: "enforce decode_failed always fails open", mode: policy.ModeEnforce, reason: FailureDecodeFailed, wantResult: true},
		{name: "observe decode_failed always fails open", mode: policy.ModeObserve, reason: FailureDecodeFailed, wantResult: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			event, span := newTestEvent()
			outcome := HandleExternalFailure(ExternalFailure{
				Ctx:    context.Background(),
				Plugin: "some_guardrail",
				Stage:  policy.StagePreRequest,
				Mode:   tc.mode,
				Reason: tc.reason,
				Detail: "some_category",
				Err:    secretErr,
				Logger: nil,
				Event:  event,
			})

			if tc.wantResult {
				if outcome.Result == nil || outcome.Result.StatusCode != http.StatusOK {
					t.Fatalf("expected pass-through result, got %+v (err=%v)", outcome.Result, outcome.Err)
				}
				if outcome.Err != nil {
					t.Fatalf("expected nil error, got %v", outcome.Err)
				}
				if outcome.Decision != "failed_open" {
					t.Fatalf("decision = %q, want failed_open", outcome.Decision)
				}
			}
			if tc.wantErr {
				if outcome.Result != nil {
					t.Fatalf("expected nil result, got %+v", outcome.Result)
				}
				pe, ok := AsPluginError(outcome.Err)
				if !ok {
					t.Fatalf("expected *PluginError, got %v", outcome.Err)
				}
				if pe.StatusCode != tc.wantStatus {
					t.Fatalf("status = %d, want %d", pe.StatusCode, tc.wantStatus)
				}
				if pe.Type != typeGuardrailUnavailable {
					t.Fatalf("type = %q, want %q", pe.Type, typeGuardrailUnavailable)
				}
				if strings.Contains(pe.Message, secretErr.Error()) {
					t.Fatalf("message leaked the underlying error: %q", pe.Message)
				}
				if strings.Contains(string(pe.Body), secretErr.Error()) {
					t.Fatalf("body leaked the underlying error: %s", pe.Body)
				}
				if !strings.Contains(string(pe.Body), typeGuardrailUnavailable) {
					t.Fatalf("body missing type: %s", pe.Body)
				}
				if outcome.Decision != "failed_closed" {
					t.Fatalf("decision = %q, want failed_closed", outcome.Decision)
				}
			}
			if span.Plugin == nil || span.Plugin.Decision != outcome.Decision {
				got := ""
				if span.Plugin != nil {
					got = span.Plugin.Decision
				}
				t.Fatalf("span decision = %q, want %q", got, outcome.Decision)
			}
		})
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
	if outcome.Decision != "failed_closed" {
		t.Fatalf("decision = %q, want failed_closed", outcome.Decision)
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
