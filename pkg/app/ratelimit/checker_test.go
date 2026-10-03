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

package ratelimit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestNoopChecker(t *testing.T) {
	if err := NewNoopChecker().Check(context.Background(), ids.New[ids.GatewayKind]()); err != nil {
		t.Fatalf("noop: %v", err)
	}
}

func TestExceededErrorString(t *testing.T) {
	err := &Exceeded{Reason: ReasonQuota}
	if got := err.Error(); got != "rate limit exceeded: quota" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestExceededHeaders(t *testing.T) {
	err := &Exceeded{Reason: ReasonBurst, Limit: 60, Remaining: 0, RetryAfter: 42 * time.Second}
	headers := err.Headers()
	if got := headers["Retry-After"]; len(got) != 1 || got[0] != "42" {
		t.Fatalf("Retry-After = %v, want [42]", got)
	}
	if got := headers["X-RateLimit-Limit"]; len(got) != 1 || got[0] != "60" {
		t.Fatalf("X-RateLimit-Limit = %v, want [60]", got)
	}
	if got := headers["X-RateLimit-Remaining"]; len(got) != 1 || got[0] != "0" {
		t.Fatalf("X-RateLimit-Remaining = %v, want [0]", got)
	}
	if got := headers["X-RateLimit-Reason"]; len(got) != 1 || got[0] != ReasonBurst {
		t.Fatalf("X-RateLimit-Reason = %v, want [%s]", got, ReasonBurst)
	}
}

func TestExceededBodyExplainsReason(t *testing.T) {
	err := &Exceeded{Reason: ReasonBurst, Limit: 60, Remaining: 0, RetryAfter: 42 * time.Second}
	var payload map[string]any
	if uerr := json.Unmarshal(err.Body(), &payload); uerr != nil {
		t.Fatalf("unmarshal body: %v", uerr)
	}
	if payload["error"] != "rate limit exceeded" {
		t.Fatalf("error = %v", payload["error"])
	}
	if payload["reason"] != ReasonBurst {
		t.Fatalf("reason = %v", payload["reason"])
	}
	if payload["limit"] != float64(60) {
		t.Fatalf("limit = %v", payload["limit"])
	}
	if payload["retry_after_seconds"] != float64(42) {
		t.Fatalf("retry_after_seconds = %v", payload["retry_after_seconds"])
	}
	msg, _ := payload["message"].(string)
	if want := "TrustGate blocked this request: gateway burst rate limit exceeded. Retry in 42s."; msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
}

func TestRetryAfterSecondsCeil(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want int
	}{
		{in: 0, want: 1},
		{in: 200 * time.Millisecond, want: 1},
		{in: time.Second, want: 1},
		{in: 1400 * time.Millisecond, want: 2},
		{in: 42 * time.Second, want: 42},
	}
	for _, tt := range tests {
		if got := RetryAfterSeconds(tt.in); got != tt.want {
			t.Fatalf("RetryAfterSeconds(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
