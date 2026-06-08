package plugins

import (
	"context"
	"time"
)

const MaxThrottleDelay = 2 * time.Second

func Throttle(ctx context.Context, delay time.Duration) error {
	if delay > MaxThrottleDelay {
		delay = MaxThrottleDelay
	}
	if delay <= 0 {
		return nil
	}
	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
