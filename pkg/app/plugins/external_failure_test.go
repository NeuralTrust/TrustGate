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

func TestClassOf(t *testing.T) {
	t.Parallel()
	cases := []struct {
		reason FailureReason
		detail string
		want   FailureClass
	}{
		{FailureTransport, "", FailureClassAvailability},
		{FailureTransport, DetailFilterNotExecuted, FailureClassAvailability},
		{FailureConfigInvalid, "", FailureClassAvailability},
		{FailureCounterUnavailable, "", FailureClassAvailability},
		{FailureDecodeFailed, "", FailureClassInput},
		{FailureInputTooLarge, "", FailureClassInput},
		{FailureInputTooLarge, DetailProviderRejectedInput, FailureClassInput},
		{FailureInputTooLarge, DetailPayloadTooLarge, FailureClassInput},
		{FailureVerdictIncomplete, DetailFilterNotExecuted, FailureClassInput},
		{FailureVerdictIncomplete, DetailInvocationPartial, FailureClassAvailability},
		{FailureConfigInvalid, DetailUnsupportedFormat, FailureClassAvailability},
		{FailureTransport, DetailAnonymizeNoOutput, FailureClassAvailability},
		{FailureVerdictIncomplete, DetailCoveragePartial, FailureClassInput},
		{FailureConfigInvalid, DetailProviderConfigRejected, FailureClassAvailability},
		{FailureVerdictIncomplete, DetailInterventionUnparsed, FailureClassInput},
		{FailureVerdictIncomplete, DetailAnonymizeNoOutput, FailureClassInput},
		{FailureVerdictIncomplete, DetailAnonymizeUnsupportedFmt, FailureClassInput},
		{FailureVerdictIncomplete, DetailAnonymizeEncodeFailed, FailureClassInput},
		{FailureVerdictIncomplete, DetailFilterNotInTemplate, FailureClassAvailability},
		{FailureVerdictIncomplete, DetailFilterStateUnspecified, FailureClassAvailability},
		{FailureVerdictIncomplete, "hate", FailureClassAvailability},
		{FailureVerdictIncomplete, "", FailureClassAvailability},
		{FailureReason("a_reason_added_later"), "", FailureClassAvailability},
	}
	for _, tc := range cases {
		if got := ClassOf(tc.reason, tc.detail); got != tc.want {
			t.Errorf("ClassOf(%q, %q) = %q, want %q", tc.reason, tc.detail, got, tc.want)
		}
	}
}

func TestIsMaskOverFinding(t *testing.T) {
	t.Parallel()
	for _, detail := range []string{DetailAnonymizeNoOutput, DetailAnonymizeUnsupportedFmt, DetailAnonymizeEncodeFailed} {
		if !IsMaskOverFinding(detail) {
			t.Errorf("IsMaskOverFinding(%q) = false", detail)
		}
	}
	for _, detail := range []string{"", DetailFilterNotExecuted, DetailInterventionUnparsed, DetailPayloadTooLarge} {
		if IsMaskOverFinding(detail) {
			t.Errorf("IsMaskOverFinding(%q) = true", detail)
		}
	}
}

// TestHandleExternalFailureModeByClass pins the outcome matrix: availability
// fails open in every mode, input is refused in the modes that block and only
// recorded in observe, and a mask over a finding is refused as the plugin's own
// block.
func TestHandleExternalFailureModeByClass(t *testing.T) {
	t.Parallel()
	finding := &PluginError{StatusCode: http.StatusForbidden, Type: "plugin_blocked", Message: "blocked by the plugin"}
	cases := []struct {
		name     string
		reason   FailureReason
		detail   string
		finding  *PluginError
		mode     policy.Mode
		decision string
		class    FailureClass
		errType  string
	}{
		{"availability enforce", FailureTransport, "", nil, policy.ModeEnforce, DecisionFailedOpen, FailureClassAvailability, ""},
		{"availability throttle", FailureTransport, "", nil, policy.ModeThrottle, DecisionFailedOpen, FailureClassAvailability, ""},
		{"availability observe", FailureTransport, "", nil, policy.ModeObserve, DecisionFailedOpen, FailureClassAvailability, ""},
		{"config enforce", FailureConfigInvalid, "", nil, policy.ModeEnforce, DecisionFailedOpen, FailureClassAvailability, ""},
		{"template enforce", FailureVerdictIncomplete, DetailFilterNotInTemplate, nil, policy.ModeEnforce, DecisionFailedOpen, FailureClassAvailability, ""},
		{"input enforce", FailureInputTooLarge, DetailProviderRejectedInput, nil, policy.ModeEnforce, DecisionFailedClosed, FailureClassInput, TypeGuardrailInputUninspectable},
		{"input throttle", FailureDecodeFailed, "", nil, policy.ModeThrottle, DecisionFailedClosed, FailureClassInput, TypeGuardrailInputUninspectable},
		{"input observe", FailureInputTooLarge, DetailProviderRejectedInput, nil, policy.ModeObserve, DecisionFailedOpen, FailureClassInput, ""},
		{"skipped filter enforce", FailureVerdictIncomplete, DetailFilterNotExecuted, nil, policy.ModeEnforce, DecisionFailedClosed, FailureClassInput, TypeGuardrailInputUninspectable},
		{"mask over finding enforce", FailureVerdictIncomplete, DetailAnonymizeNoOutput, finding, policy.ModeEnforce, DecisionBlocked, FailureClassInput, "plugin_blocked"},
		{"mask over finding observe", FailureVerdictIncomplete, DetailAnonymizeNoOutput, finding, policy.ModeObserve, DecisionFailedOpen, FailureClassInput, ""},
		{"mask without a finding enforce", FailureVerdictIncomplete, DetailAnonymizeNoOutput, nil, policy.ModeEnforce, DecisionFailedClosed, FailureClassInput, TypeGuardrailInputUninspectable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			event, span := newTestEvent()
			out := HandleExternalFailure(ExternalFailure{
				Ctx:     context.Background(),
				Plugin:  "some_guardrail",
				Stage:   policy.StagePreRequest,
				Mode:    tc.mode,
				Reason:  tc.reason,
				Detail:  tc.detail,
				Finding: tc.finding,
				Err:     errors.New("dial tcp 10.0.0.1:443: connection refused"),
				Event:   event,
			})
			if out.Decision != tc.decision || out.Class != tc.class {
				t.Fatalf("decision/class = %q/%q, want %q/%q", out.Decision, out.Class, tc.decision, tc.class)
			}
			if span.Plugin == nil || span.Plugin.Decision != SpanDecisionFromOutcome(tc.decision) {
				t.Fatalf("span decision = %+v, want %q", span.Plugin, SpanDecisionFromOutcome(tc.decision))
			}
			if tc.errType == "" {
				if out.Err != nil || out.Result == nil || out.Result.StatusCode != http.StatusOK {
					t.Fatalf("want a pass-through, got result=%+v err=%+v", out.Result, out.Err)
				}
				return
			}
			if out.Result != nil || out.Err == nil || out.Err.Type != tc.errType || out.Err.StatusCode != http.StatusForbidden {
				t.Fatalf("want a 403 %q, got result=%+v err=%+v", tc.errType, out.Result, out.Err)
			}
		})
	}
}

func TestUninspectableErrorNeverCarriesTheProviderError(t *testing.T) {
	t.Parallel()
	out := HandleExternalFailure(ExternalFailure{
		Plugin:  "some_guardrail",
		Mode:    policy.ModeEnforce,
		Reason:  FailureInputTooLarge,
		Message: "  custom refusal  ",
		Err:     errors.New("POST https://secret.internal/v1: 400"),
	})
	if out.Err == nil || out.Err.Message != "custom refusal" {
		t.Fatalf("err = %+v, want the configured message", out.Err)
	}
	if strings.Contains(string(out.Err.Body), "secret.internal") || !strings.Contains(string(out.Err.Body), TypeGuardrailInputUninspectable) {
		t.Fatalf("body = %s", out.Err.Body)
	}
	if def := UninspectableError(""); def.Message != DefaultUninspectableMessage {
		t.Fatalf("default message = %q", def.Message)
	}
}

func TestHandleExternalFailureNilEventAndLoggerAreSafe(t *testing.T) {
	t.Parallel()
	out := HandleExternalFailure(ExternalFailure{
		Plugin: "some_guardrail",
		Stage:  policy.StagePreRequest,
		Mode:   policy.ModeEnforce,
		Reason: FailureTransport,
		Err:    errors.New("boom"),
	})
	if out.Result == nil || out.Result.StatusCode != http.StatusOK {
		t.Fatalf("result = %+v, want a pass-through", out.Result)
	}
}

func TestExternalStreamOutcome(t *testing.T) {
	t.Parallel()
	base := errors.New("boom")
	block := &SegmentVerdict{Type: "plugin_blocked", Message: "masking could not be applied"}

	t.Run("availability is the typed error in every mode", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			verdict, err := ExternalStreamOutcome("g", mode, FailureTransport, "", nil, base)
			var failure *ExternalStreamFailure
			if verdict != nil || !errors.As(err, &failure) || failure.Class != FailureClassAvailability {
				t.Fatalf("%s: verdict=%+v err=%v", mode, verdict, err)
			}
		}
	})
	t.Run("input in observe is the typed error", func(t *testing.T) {
		t.Parallel()
		verdict, err := ExternalStreamOutcome("g", policy.ModeObserve, FailureInputTooLarge, DetailProviderRejectedInput, nil, base)
		var failure *ExternalStreamFailure
		if verdict != nil || !errors.As(err, &failure) || failure.Class != FailureClassInput {
			t.Fatalf("verdict=%+v err=%v", verdict, err)
		}
	})
	t.Run("input in enforce is a cut carrying the failure", func(t *testing.T) {
		t.Parallel()
		verdict, err := ExternalStreamOutcome("g", policy.ModeEnforce, FailureInputTooLarge, DetailProviderRejectedInput, nil, base)
		if err != nil || verdict == nil || !verdict.Block || verdict.Type != TypeGuardrailInputUninspectable ||
			verdict.Failure == nil || verdict.Failure.Reason != FailureInputTooLarge {
			t.Fatalf("verdict=%+v err=%v", verdict, err)
		}
	})
	t.Run("a mask over a finding in observe still reports the finding", func(t *testing.T) {
		t.Parallel()
		template := &SegmentVerdict{Type: "plugin_blocked", Fingerprints: []string{"fp"}}
		verdict, err := ExternalStreamOutcome("g", policy.ModeObserve, FailureVerdictIncomplete, DetailAnonymizeNoOutput, template, base)
		if err != nil || verdict == nil || verdict.Block || verdict.HasTransform ||
			len(verdict.Fingerprints) != 1 || verdict.Incomplete == nil {
			t.Fatalf("verdict=%+v err=%v", verdict, err)
		}
	})
	t.Run("a mask over a finding cuts with the plugin's own verdict", func(t *testing.T) {
		t.Parallel()
		verdict, err := ExternalStreamOutcome("g", policy.ModeEnforce, FailureVerdictIncomplete, DetailAnonymizeNoOutput, block, base)
		if err != nil || verdict == nil || !verdict.Block || verdict.Type != "plugin_blocked" ||
			verdict.Message != block.Message || verdict.Failure == nil || verdict.Failure.Detail != DetailAnonymizeNoOutput {
			t.Fatalf("verdict=%+v err=%v", verdict, err)
		}
		if block.Failure != nil {
			t.Fatal("the plugin's verdict template was mutated")
		}
	})
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
