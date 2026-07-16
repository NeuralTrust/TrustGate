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
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type stubTiers struct {
	tier string
	err  error
}

func (s stubTiers) Tier(context.Context, ids.GatewayID) (string, error) {
	return s.tier, s.err
}

type stubCounter struct {
	burst      int64
	burstTTL   time.Duration
	burstErr   error
	quota      int64
	quotaErr   error
	quotaCalls int
}

func (s *stubCounter) IncrBurst(context.Context, ids.GatewayID) (int64, time.Duration, error) {
	return s.burst, s.burstTTL, s.burstErr
}

func (s *stubCounter) IncrQuota(context.Context, ids.GatewayID, string) (int64, error) {
	s.quotaCalls++
	return s.quota, s.quotaErr
}

func TestCheckerBurstExceeded(t *testing.T) {
	c := NewChecker(stubTiers{tier: "free"}, &stubCounter{burst: 121, burstTTL: 42 * time.Second}, nil)
	err := c.Check(context.Background(), ids.New[ids.GatewayKind]())
	var ex *Exceeded
	if !errors.As(err, &ex) {
		t.Fatalf("err = %v, want Exceeded", err)
	}
	if ex.Reason != ReasonBurst || ex.Limit != 120 {
		t.Fatalf("got %+v", ex)
	}
	if ex.Remaining != 0 {
		t.Fatalf("Remaining = %d, want 0", ex.Remaining)
	}
	if ex.RetryAfter != 42*time.Second {
		t.Fatalf("RetryAfter = %v, want 42s", ex.RetryAfter)
	}
}

func TestCheckerBurstAtLimitAllowed(t *testing.T) {
	counter := &stubCounter{burst: 120, burstTTL: time.Minute, quota: 1}
	c := NewChecker(stubTiers{tier: "free"}, counter, nil)
	if err := c.Check(context.Background(), ids.New[ids.GatewayKind]()); err != nil {
		t.Fatalf("count==limit must allow, got %v", err)
	}
	if counter.quotaCalls != 1 {
		t.Fatalf("quotaCalls = %d, want 1 (burst allowed then quota checked)", counter.quotaCalls)
	}
}

func TestCheckerQuotaExceeded(t *testing.T) {
	c := NewChecker(stubTiers{tier: "free"}, &stubCounter{burst: 1, burstTTL: time.Minute, quota: 25_001}, nil)
	err := c.Check(context.Background(), ids.New[ids.GatewayKind]())
	var ex *Exceeded
	if !errors.As(err, &ex) {
		t.Fatalf("err = %v, want Exceeded", err)
	}
	if ex.Reason != ReasonQuota || ex.Limit != 25_000 {
		t.Fatalf("got %+v", ex)
	}
}

func TestCheckerQuotaAtLimitAllowed(t *testing.T) {
	c := NewChecker(stubTiers{tier: "free"}, &stubCounter{burst: 1, burstTTL: time.Minute, quota: 25_000}, nil)
	if err := c.Check(context.Background(), ids.New[ids.GatewayKind]()); err != nil {
		t.Fatalf("quota==limit must allow, got %v", err)
	}
}

func TestCheckerStandardLimits(t *testing.T) {
	c := NewChecker(stubTiers{tier: "standard"}, &stubCounter{burst: 601, burstTTL: time.Second}, nil)
	err := c.Check(context.Background(), ids.New[ids.GatewayKind]())
	var ex *Exceeded
	if !errors.As(err, &ex) {
		t.Fatalf("err = %v, want Exceeded", err)
	}
	if ex.Reason != ReasonBurst || ex.Limit != 600 {
		t.Fatalf("got %+v", ex)
	}
}

func TestCheckerEnterpriseSkipsQuota(t *testing.T) {
	counter := &stubCounter{burst: 1, burstTTL: time.Minute}
	c := NewChecker(stubTiers{tier: "enterprise"}, counter, nil)
	if err := c.Check(context.Background(), ids.New[ids.GatewayKind]()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if counter.quotaCalls != 0 {
		t.Fatalf("quotaCalls = %d, want 0", counter.quotaCalls)
	}
}

func TestCheckerEnterpriseBurstExceeded(t *testing.T) {
	c := NewChecker(stubTiers{tier: "enterprise"}, &stubCounter{burst: 5_001, burstTTL: 15 * time.Second}, nil)
	err := c.Check(context.Background(), ids.New[ids.GatewayKind]())
	var ex *Exceeded
	if !errors.As(err, &ex) {
		t.Fatalf("err = %v, want Exceeded", err)
	}
	if ex.Reason != ReasonBurst || ex.Limit != 5_000 {
		t.Fatalf("got %+v", ex)
	}
}

func TestCheckerUnknownTierUnavailable(t *testing.T) {
	c := NewChecker(stubTiers{tier: "gold"}, &stubCounter{burst: 1}, nil)
	if err := c.Check(context.Background(), ids.New[ids.GatewayKind]()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestCheckerMissingGatewayUnavailable(t *testing.T) {
	c := NewChecker(stubTiers{err: commonerrors.ErrNotFound}, &stubCounter{}, nil)
	if err := c.Check(context.Background(), ids.New[ids.GatewayKind]()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestCheckerTierLoadErrorFailOpen(t *testing.T) {
	c := NewChecker(stubTiers{err: errors.New("db down")}, &stubCounter{burst: 999}, nil)
	if err := c.Check(context.Background(), ids.New[ids.GatewayKind]()); err != nil {
		t.Fatalf("want fail-open nil, got %v", err)
	}
}

func TestCheckerRedisFailOpen(t *testing.T) {
	c := NewChecker(stubTiers{tier: "free"}, &stubCounter{burstErr: errors.New("redis down")}, nil)
	if err := c.Check(context.Background(), ids.New[ids.GatewayKind]()); err != nil {
		t.Fatalf("want fail-open nil, got %v", err)
	}
}

func TestCheckerQuotaRedisFailOpen(t *testing.T) {
	c := NewChecker(stubTiers{tier: "free"}, &stubCounter{burst: 1, burstTTL: time.Minute, quotaErr: errors.New("redis down")}, nil)
	if err := c.Check(context.Background(), ids.New[ids.GatewayKind]()); err != nil {
		t.Fatalf("want fail-open nil, got %v", err)
	}
}

func TestCheckerBurstBlocksBeforeQuota(t *testing.T) {
	counter := &stubCounter{burst: 121, burstTTL: time.Second, quota: 1}
	c := NewChecker(stubTiers{tier: "free"}, counter, nil)
	err := c.Check(context.Background(), ids.New[ids.GatewayKind]())
	var ex *Exceeded
	if !errors.As(err, &ex) || ex.Reason != ReasonBurst {
		t.Fatalf("err = %v, want burst Exceeded", err)
	}
	if counter.quotaCalls != 0 {
		t.Fatalf("quota must not run after burst exceed, calls=%d", counter.quotaCalls)
	}
}

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
	err := &Exceeded{Reason: ReasonBurst, Limit: 120, Remaining: 0, RetryAfter: 42 * time.Second}
	headers := err.Headers()
	if got := headers["Retry-After"]; len(got) != 1 || got[0] != "42" {
		t.Fatalf("Retry-After = %v, want [42]", got)
	}
	if got := headers["X-RateLimit-Limit"]; len(got) != 1 || got[0] != "120" {
		t.Fatalf("X-RateLimit-Limit = %v, want [120]", got)
	}
	if got := headers["X-RateLimit-Remaining"]; len(got) != 1 || got[0] != "0" {
		t.Fatalf("X-RateLimit-Remaining = %v, want [0]", got)
	}
	if got := headers["X-RateLimit-Reason"]; len(got) != 1 || got[0] != ReasonBurst {
		t.Fatalf("X-RateLimit-Reason = %v, want [%s]", got, ReasonBurst)
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
