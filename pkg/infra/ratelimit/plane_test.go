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
	"strings"
	"testing"
	"time"

	appratelimit "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newPlaneLimiterTest(
	t *testing.T,
	cfg config.MCPPlaneRateLimitConfig,
) (appratelimit.PlaneLimiter, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close redis client: %v", err)
		}
	})
	return NewPlaneLimiter(client, "server-secret", cfg), server
}

func planeTestConfig() config.MCPPlaneRateLimitConfig {
	return config.MCPPlaneRateLimitConfig{
		DefaultLimit:    5,
		CredentialLimit: 2,
		Window:          time.Minute,
	}
}

func TestPlaneLimiterAllowsUpToTheClassLimit(t *testing.T) {
	limiter, _ := newPlaneLimiterTest(t, planeTestConfig())
	ctx := context.Background()

	for i := 1; i <= 2; i++ {
		if err := limiter.Check(ctx, appratelimit.PlaneClassCredential, "gw|1.2.3.4"); err != nil {
			t.Fatalf("attempt %d refused: %v", i, err)
		}
	}

	err := limiter.Check(ctx, appratelimit.PlaneClassCredential, "gw|1.2.3.4")
	var exceeded *appratelimit.PlaneLimitExceeded
	if !errors.As(err, &exceeded) {
		t.Fatalf("expected the third attempt to be refused, got %v", err)
	}
	if exceeded.RetryAfter < time.Second {
		t.Fatalf("retry-after must be at least a second, got %v", exceeded.RetryAfter)
	}
}

// The two classes are separate budgets: spending the credential one must not
// cost a client its discovery documents.
func TestPlaneLimiterCountsClassesApart(t *testing.T) {
	limiter, _ := newPlaneLimiterTest(t, planeTestConfig())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_ = limiter.Check(ctx, appratelimit.PlaneClassCredential, "gw|1.2.3.4")
	}
	if err := limiter.Check(ctx, appratelimit.PlaneClassDefault, "gw|1.2.3.4"); err != nil {
		t.Fatalf("default class should still have room: %v", err)
	}
}

func TestPlaneLimiterCountsSubjectsApart(t *testing.T) {
	limiter, _ := newPlaneLimiterTest(t, planeTestConfig())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_ = limiter.Check(ctx, appratelimit.PlaneClassCredential, "gw|1.2.3.4")
	}
	if err := limiter.Check(ctx, appratelimit.PlaneClassCredential, "gw|5.6.7.8"); err != nil {
		t.Fatalf("a different origin should have its own bucket: %v", err)
	}
	if err := limiter.Check(ctx, appratelimit.PlaneClassCredential, "other-gw|1.2.3.4"); err != nil {
		t.Fatalf("a different host should have its own bucket: %v", err)
	}
}

// A Redis dump must not read as a list of who called this gateway and when.
func TestPlaneLimiterKeysDoNotCarryTheOrigin(t *testing.T) {
	limiter, server := newPlaneLimiterTest(t, planeTestConfig())
	if err := limiter.Check(context.Background(), appratelimit.PlaneClassCredential, "gw|1.2.3.4"); err != nil {
		t.Fatalf("check: %v", err)
	}

	keys := server.Keys()
	if len(keys) != 1 {
		t.Fatalf("expected one bucket, got %v", keys)
	}
	if strings.Contains(keys[0], "1.2.3.4") || strings.Contains(keys[0], "gw|") {
		t.Fatalf("bucket key leaks the origin: %s", keys[0])
	}
	if !strings.HasPrefix(keys[0], planeBucketPrefix+":credential:") {
		t.Fatalf("unexpected key shape: %s", keys[0])
	}
}

func TestPlaneLimiterWindowExpires(t *testing.T) {
	limiter, server := newPlaneLimiterTest(t, planeTestConfig())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_ = limiter.Check(ctx, appratelimit.PlaneClassCredential, "gw|1.2.3.4")
	}
	server.FastForward(time.Minute + time.Second)

	if err := limiter.Check(ctx, appratelimit.PlaneClassCredential, "gw|1.2.3.4"); err != nil {
		t.Fatalf("the window should have expired: %v", err)
	}
}

func TestPlaneLimiterWithoutRedisReportsUnavailable(t *testing.T) {
	limiter := NewPlaneLimiter(nil, "server-secret", planeTestConfig())
	err := limiter.Check(context.Background(), appratelimit.PlaneClassDefault, "gw|1.2.3.4")
	if !errors.Is(err, appratelimit.ErrPlaneLimiterUnavailable) {
		t.Fatalf("expected an unavailable limiter, got %v", err)
	}
}

// An unnamed origin or an unknown class is allowed rather than guessed at.
func TestPlaneLimiterSkipsUnusableInput(t *testing.T) {
	limiter, server := newPlaneLimiterTest(t, planeTestConfig())
	ctx := context.Background()

	if err := limiter.Check(ctx, appratelimit.PlaneClassDefault, ""); err != nil {
		t.Fatalf("empty subject: %v", err)
	}
	if err := limiter.Check(ctx, appratelimit.PlaneClass(9), "gw|1.2.3.4"); err != nil {
		t.Fatalf("unknown class: %v", err)
	}
	if keys := server.Keys(); len(keys) != 0 {
		t.Fatalf("nothing should have been counted, got %v", keys)
	}
}
