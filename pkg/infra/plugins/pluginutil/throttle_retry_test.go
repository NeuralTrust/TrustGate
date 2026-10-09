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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubRejection struct {
	status      int
	configShape bool
	retryAfter  time.Duration
}

func (e *stubRejection) Error() string             { return "rejected" }
func (e *stubRejection) Rejection() (int, bool)    { return e.status, e.configShape }
func (e *stubRejection) RetryAfter() time.Duration { return e.retryAfter }

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, 3*time.Second, ParseRetryAfter("3", now))
	assert.Equal(t, 5*time.Second, ParseRetryAfter(now.Add(5*time.Second).UTC().Format(http.TimeFormat), now))
	assert.Zero(t, ParseRetryAfter("", now))
	assert.Zero(t, ParseRetryAfter("soon", now))
	assert.Zero(t, ParseRetryAfter(now.Add(-time.Hour).UTC().Format(http.TimeFormat), now))
}

func TestRetryThrottledOnceRetriesOnlyARateAndOnlyOnce(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		err   error
		calls int
	}{
		"a rate":             {&stubRejection{status: 429}, 2},
		"an exhausted quota": {&stubRejection{status: 429, configShape: true}, 1},
		"a server error":     {&stubRejection{status: 503}, 1},
		"a bare error":       {errors.New("boom"), 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := RetryThrottledOnce(ctx, func(context.Context) (int, error) { calls++; return 0, tc.err })
			require.Error(t, err)
			assert.Equal(t, tc.calls, calls)
		})
	}
	t.Run("success on the retry", func(t *testing.T) {
		t.Parallel()
		calls := 0
		v, err := RetryThrottledOnce(context.Background(), func(context.Context) (int, error) {
			calls++
			if calls == 1 {
				return 0, &stubRejection{status: 429}
			}
			return 7, nil
		})
		require.NoError(t, err)
		assert.Equal(t, 7, v)
	})
}

func TestRetryThrottledOnceHonoursRetryAfterOnlyWhenItFits(t *testing.T) {
	t.Parallel()
	run := func(retryAfter, budget time.Duration) time.Duration {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		var at []time.Time
		_, _ = RetryThrottledOnce(ctx, func(context.Context) (int, error) {
			at = append(at, time.Now())
			return 0, &stubRejection{status: 429, retryAfter: retryAfter}
		})
		require.Len(t, at, 2)
		return at[1].Sub(at[0])
	}
	assert.GreaterOrEqual(t, run(time.Second, 10*time.Second), 950*time.Millisecond, "it fits, so it is honoured")
	assert.Less(t, run(time.Minute, 4*time.Second), 900*time.Millisecond, "it does not fit, so a short backoff is used")
}

func TestRetryFirstRoundThrottleSkipsAChunkThatWaited(t *testing.T) {
	t.Parallel()
	calls := 0
	_, _ = RetryFirstRoundThrottle(context.Background(), 4, 4, func(context.Context) (int, error) { calls++; return 0, &stubRejection{status: 429} })
	assert.Equal(t, 1, calls)
	calls = 0
	_, _ = RetryFirstRoundThrottle(context.Background(), 3, 4, func(context.Context) (int, error) { calls++; return 0, &stubRejection{status: 429} })
	assert.Equal(t, 2, calls)
}
