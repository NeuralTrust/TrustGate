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
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// TestHandleCounterFailureAlwaysFailsOpen proves the rule that sets
// HandleCounterFailure apart from HandleExternalFailure: our own
// infrastructure fails open in every mode, including enforce, where an
// external guardrail would fail closed.
func TestHandleCounterFailureAlwaysFailsOpen(t *testing.T) {
	t.Parallel()

	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeThrottle, policy.ModeObserve} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			event, span := newTestEvent()
			result, err := HandleCounterFailure(CounterFailure{
				Ctx:    context.Background(),
				Plugin: "rate_limiter",
				Stage:  policy.StagePreRequest,
				Mode:   mode,
				Detail: "read",
				Err:    errors.New("dial tcp 10.0.0.1:6379: connection refused"),
				Event:  event,
			})

			if err != nil {
				t.Fatalf("expected nil error on a genuine outage, got %v", err)
			}
			if result == nil || result.StatusCode != http.StatusOK {
				t.Fatalf("expected pass-through result, got %+v", result)
			}
			if span.Plugin == nil || span.Plugin.Decision != "failed_open" {
				got := ""
				if span.Plugin != nil {
					got = span.Plugin.Decision
				}
				t.Fatalf("span decision = %q, want failed_open", got)
			}
		})
	}
}

// TestHandleCounterFailureNilEventAndLoggerAreSafe proves the helper never
// panics when a caller omits the optional Event or Logger, and that a nil
// Logger still does not crash the one Warn line (it falls back to the slog
// default logger rather than requiring one of its own — none of
// rate_limiter, per_tool_rate_limiter or token_rate_limiter carry one).
func TestHandleCounterFailureNilEventAndLoggerAreSafe(t *testing.T) {
	t.Parallel()
	result, err := HandleCounterFailure(CounterFailure{
		Plugin: "token_rate_limiter",
		Stage:  policy.StagePostResponse,
		Mode:   policy.ModeEnforce,
		Detail: "record_tokens",
		Err:    errors.New("boom"),
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || result.StatusCode != http.StatusOK {
		t.Fatalf("expected pass-through result, got %+v", result)
	}
}

// TestHandleCounterFailureCanceledContextIsNotAnOutage proves item 1 of the
// RUN-1675 review: a ctx the caller itself canceled or let deadline out is
// not our counter store being down. HandleCounterFailure must return the
// original error unchanged — no failed_open decision, no counter_unavailable
// telemetry, no Warn log — exactly as if this helper did not intervene.
func TestHandleCounterFailureCanceledContextIsNotAnOutage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ctx  func(t *testing.T) context.Context
	}{
		{
			name: "canceled",
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
		},
		{
			name: "deadline exceeded",
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				t.Cleanup(cancel)
				return ctx
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			event, span := newTestEvent()
			origErr := errors.New("rate_limiter: count window: context canceled")

			result, err := HandleCounterFailure(CounterFailure{
				Ctx:    tt.ctx(t),
				Plugin: "rate_limiter",
				Stage:  policy.StagePreRequest,
				Mode:   policy.ModeObserve,
				Detail: "read",
				Err:    origErr,
				Event:  event,
			})

			if result != nil {
				t.Fatalf("expected no pass-through result on a canceled ctx, got %+v", result)
			}
			if !errors.Is(err, origErr) {
				t.Fatalf("expected the original error unchanged, got %v", err)
			}
			if span.Plugin != nil && span.Plugin.Decision != "" {
				t.Fatalf("a canceled ctx must not set a decision, got %q", span.Plugin.Decision)
			}
		})
	}
}
