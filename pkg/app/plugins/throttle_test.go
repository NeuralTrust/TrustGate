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
