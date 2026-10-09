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
