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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// TestHandleCounterFailureAlwaysFailsOpen proves our own infrastructure fails
// open in every mode, including enforce.
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

// redisReplyError stands in for the error go-redis returns for a Redis error
// reply: CounterErrorClass recognises it by its RedisError method alone.
type redisReplyError string

func (e redisReplyError) Error() string { return string(e) }
func (redisReplyError) RedisError()     {}

func TestCounterErrorClass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: ""},
		{name: "replica", err: redisReplyError("READONLY You can't write against a read only replica."), want: "readonly"},
		{name: "wrapped oom", err: fmt.Errorf("rate_limiter: record request: %w", redisReplyError("OOM command not allowed when used memory > 'maxmemory'.")), want: "oom"},
		{name: "bgsave failing", err: redisReplyError("MISCONF Redis is configured to save RDB snapshots, but it's currently unable to persist to disk."), want: "misconf"},
		{name: "acl", err: redisReplyError("NOPERM User reader has no permissions to run the 'multi' command"), want: "noperm"},
		{name: "aborted transaction", err: redisReplyError("EXECABORT Transaction discarded because of previous errors."), want: "execabort"},
		{name: "script on a replica", err: redisReplyError("READONLY You can't write against a read only replica. script: 9e8f, on @user_script:1."), want: "readonly"},
		{name: "generic err", err: redisReplyError("ERR unknown command 'MULTI'"), want: "err"},
		{name: "unlisted code", err: redisReplyError("SOMEPROXY refused ratelimit:plugin-1:consumer:c-1"), want: "redis_other"},
		{name: "dial refused", err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}, want: "connection"},
		{name: "read deadline", err: &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, want: "timeout"},
		{name: "context deadline", err: fmt.Errorf("count window: %w", context.DeadlineExceeded), want: "timeout"},
		{name: "server hung up", err: io.EOF, want: "connection"},
		{name: "plain error", err: errors.New("dial tcp: connection refused"), want: "unknown"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := CounterErrorClass(tt.err); got != tt.want {
				t.Fatalf("CounterErrorClass(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestLogCounterFailureCarriesErrorClass(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	LogCounterFailure(CounterFailure{
		Ctx:    context.Background(),
		Plugin: "rate_limiter",
		Stage:  policy.StagePreRequest,
		Mode:   policy.ModeEnforce,
		Detail: "record",
		Err:    redisReplyError("READONLY You can't write against a read only replica."),
		Logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	}, DecisionFailedOpen)

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log line is not JSON: %v (%q)", err, buf.String())
	}
	if line["error_class"] != "readonly" {
		t.Fatalf("error_class = %v, want readonly (line %s)", line["error_class"], buf.String())
	}
}
