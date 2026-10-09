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

package bedrockguardrail

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThrottleRetriesAreBoundedPerCredential(t *testing.T) {
	t.Parallel()
	throttled := throttlingError(t)
	always := make([]error, 200)
	for i := range always {
		always[i] = throttled
	}
	client := &sequencedClient{errs: always, output: allowOutput()}
	p := pluginWith(client)
	p.guardrails.backoff = time.Millisecond
	mine := awsCredentials{region: "us-east-1", accessKeyID: "AKIAMINE", secretAccessKey: "secret"}
	other := awsCredentials{region: "us-east-1", accessKeyID: "AKIAOTHER", secretAccessKey: "secret"}
	in := buildApplyInput(testSettings, "some text", "INPUT")

	const calls = 12
	start := time.Now()
	for i := 0; i < calls; i++ {
		_, err := p.guardrails.ApplyWithBackoff(context.Background(), mine, in, callLimits{})
		require.Error(t, err)
		assert.Equal(t, "throttled", throttleDetail(err))
	}
	retries := client.count() - calls
	allowed := throttleRetryBurst + int(time.Since(start).Seconds()*throttleRetriesPerSecond) + 1
	assert.GreaterOrEqual(t, retries, throttleRetryBurst, "the burst is spent")
	assert.LessOrEqual(t, retries, allowed, "retries stop when the credential's budget is empty")

	before := client.count()
	_, err := p.guardrails.ApplyWithBackoff(context.Background(), other, in, callLimits{})
	require.Error(t, err)
	assert.Equal(t, maxApplyAttempts, client.count()-before, "another credential has a budget of its own")
}

func TestANoRetryCallLimitSendsAThrottleBackAsItIs(t *testing.T) {
	t.Parallel()
	client := &sequencedClient{errs: []error{throttlingError(t), throttlingError(t)}, output: allowOutput()}
	p := pluginWith(client)
	_, err := p.guardrails.ApplyWithBackoff(context.Background(), awsCredentials{}, buildApplyInput(testSettings, "t", "INPUT"),
		callLimits{noThrottleRetry: true})
	require.Error(t, err)
	assert.Equal(t, 1, client.count())
}

func TestCallLimitsForABigTextTakeEveryRetryAway(t *testing.T) {
	t.Parallel()
	assert.Equal(t, callLimits{}, callLimitsFor(maxStreamWindowBytes))
	assert.Equal(t, callLimits{noThrottleRetry: true, noTransientRetry: true}, callLimitsFor(maxStreamWindowBytes+1))
}

func throttleDetail(err error) string {
	_, detail := classifyApplyErr(err)
	return detail
}

func TestJitterStaysBelowItsBound(t *testing.T) {
	t.Parallel()
	assert.Zero(t, jitter(0))
	assert.Zero(t, jitter(-time.Second))
	seen := map[time.Duration]struct{}{}
	for i := 0; i < 64; i++ {
		j := jitter(200 * time.Millisecond)
		assert.GreaterOrEqual(t, j, time.Duration(0))
		assert.Less(t, j, 200*time.Millisecond)
		seen[j] = struct{}{}
	}
	assert.Greater(t, len(seen), 1, "the jitter varies")
}

// A throttle retry that the deadline does not leave time for is never sent, so
// it must not spend a token of the credential's budget: a burst of calls near
// their deadline would otherwise empty the budget without one retry.
func TestARetryTheDeadlineDoesNotAllowSpendsNoToken(t *testing.T) {
	t.Parallel()
	client := &sequencedClient{errs: []error{throttlingError(t), throttlingError(t), throttlingError(t)}, output: allowOutput()}
	p := pluginWith(client)
	creds := awsCredentials{region: "us-east-1", accessKeyID: "AKIAMINE", secretAccessKey: "secret"}
	in := buildApplyInput(testSettings, "some text", "INPUT")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := p.guardrails.ApplyWithBackoff(ctx, creds, in, callLimits{})

	require.Error(t, err)
	assert.Equal(t, "throttled", throttleDetail(err))
	assert.Equal(t, 1, client.count(), "the wait would have run past the deadline")
	assert.InDelta(t, float64(throttleRetryBurst), p.guardrails.throttleBudget(creds).Tokens(), 0.5, "no token was spent")
}

func TestAThrottledStreamEntryThatNeverClosedExpires(t *testing.T) {
	t.Parallel()
	p := pluginWith(allowing())
	now := time.Now()
	p.throttledStreams.Store("abandoned", now.Add(-throttledStreamTTL-time.Minute))
	p.throttledStreams.Store("live", now.Add(-time.Minute))

	p.markStreamThrottled("fresh", now)

	assert.False(t, p.streamThrottled("abandoned"), "an entry whose closing segment never came is swept")
	assert.True(t, p.streamThrottled("live"))
	assert.True(t, p.streamThrottled("fresh"))
	p.forgetStreamThrottle("fresh")
	assert.False(t, p.streamThrottled("fresh"), "the closing segment removes it")
	assert.False(t, p.streamThrottled(""), "a stream with no identity is never marked")
}

// Any of the three operations on the throttled streams sweeps the entries whose
// closing never came, so a pod that only reads or only closes streams cannot grow
// the map.
func TestAnyOperationOnTheThrottledStreamsSweepsTheExpiredOnes(t *testing.T) {
	t.Parallel()
	expired := func() *Plugin {
		p := pluginWith(allowing())
		p.throttledStreams.Store("abandoned", time.Now().Add(-throttledStreamTTL-time.Minute))
		return p
	}
	cases := map[string]func(p *Plugin){
		"a read":  func(p *Plugin) { p.streamThrottled("someone") },
		"a close": func(p *Plugin) { p.forgetStreamThrottle("someone") },
		"a mark":  func(p *Plugin) { p.markStreamThrottled("someone", time.Now()) },
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := expired()
			op(p)
			_, still := p.throttledStreams.Load("abandoned")
			assert.False(t, still)
		})
	}
}
