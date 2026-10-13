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

package pluginutil

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

// RetryAfterer is implemented by the error of a provider that said how long to
// wait (a Retry-After header).
type RetryAfterer interface {
	RetryAfter() time.Duration
}

// ParseRetryAfter reads a Retry-After header, either a number of seconds or an
// HTTP date. It is zero when the header is absent, malformed or in the past.
func ParseRetryAfter(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(header); err == nil {
		return max(0, time.Duration(secs)*time.Second)
	}
	if at, err := http.ParseTime(header); err == nil {
		return max(0, at.Sub(now))
	}
	return 0
}

// IsThrottle reports whether err is a provider's 429 that is a rate and not an
// exhausted quota (configuration).
func IsThrottle(err error) bool {
	var rejection Rejection
	if !errors.As(err, &rejection) {
		return false
	}
	status, configShaped := rejection.Rejection()
	return status == http.StatusTooManyRequests && !configShaped
}

// RetryThrottledOnce calls fn and, when it fails with a throttle, calls it once
// more. The wait is textchunk.RetryWait, which is the provider's Retry-After when
// it fits in half of the time ctx has left and otherwise a short backoff; it is
// not counted in the call's Outcome.Took. A wait that ctx
// cannot afford is not taken and the throttle is returned as it is. Only a throttle is retried: any other failure, and a
// second throttle, is returned unchanged.
func RetryThrottledOnce[T any](ctx context.Context, fn func(ctx context.Context) (T, error)) (T, error) {
	v, err := fn(ctx)
	if err == nil || !IsThrottle(err) {
		return v, err
	}
	var retryAfter time.Duration
	var ra RetryAfterer
	if errors.As(err, &ra) {
		retryAfter = ra.RetryAfter()
	}
	wait := textchunk.RetryWait(ctx, retryAfter)
	if !textchunk.Pause(ctx, wait) {
		return v, err
	}
	return fn(ctx)
}

// RetryFirstRoundThrottle is RetryThrottledOnce for a call of a textchunk.Run:
// only a call of the first round the Run's schedule releases
// (textchunk.FirstRound) is retried. A chunk that waited behind the request's
// own was queued by its size, and its throttle is read as that.
func RetryFirstRoundThrottle[T any](ctx context.Context, fn func(ctx context.Context) (T, error)) (T, error) {
	if !textchunk.FirstRound(ctx) {
		return fn(ctx)
	}
	return RetryThrottledOnce(ctx, fn)
}
