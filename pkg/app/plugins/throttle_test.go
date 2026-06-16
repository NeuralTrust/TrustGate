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
	"testing"
	"time"
)

func TestThrottle_NonPositiveReturnsImmediately(t *testing.T) {
	t.Parallel()
	start := time.Now()
	if err := Throttle(context.Background(), 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("zero delay should not block, slept %s", elapsed)
	}
}

func TestThrottle_CapsDelay(t *testing.T) {
	t.Parallel()
	start := time.Now()
	if err := Throttle(context.Background(), MaxThrottleDelay+time.Hour); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > MaxThrottleDelay+time.Second {
		t.Fatalf("delay should be capped at %s, slept %s", MaxThrottleDelay, elapsed)
	}
}

func TestThrottle_HonorsContextCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Throttle(ctx, MaxThrottleDelay); err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
}
