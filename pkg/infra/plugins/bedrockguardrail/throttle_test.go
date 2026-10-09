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
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// throttlingError is what the SDK makes of AWS's own throttling answer, served
// over HTTP in the documented wire shape.
func throttlingError(t *testing.T) error {
	t.Helper()
	return applyGuardrailAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Amzn-ErrorType", "ThrottlingException:http://internal.amazon.com/coral/com.amazonaws.bedrock/")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"Too many requests, please wait before trying again."}`))
	})
}

// sequencedClient answers each call from errs in order and then with output.
type sequencedClient struct {
	mu     sync.Mutex
	calls  int
	errs   []error
	output *bedrockruntime.ApplyGuardrailOutput
}

func (c *sequencedClient) ApplyGuardrail(
	_ context.Context,
	_ *bedrockruntime.ApplyGuardrailInput,
	_ ...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls <= len(c.errs) {
		return nil, c.errs[c.calls-1]
	}
	return c.output, nil
}

func (c *sequencedClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// A throttled block is retried, inside the block's own deadline, instead of
// being released uninspected on the first answer.
func TestStreamBlockRetriesAThrottleWithinItsDeadline(t *testing.T) {
	t.Parallel()
	throttled := throttlingError(t)
	client := &sequencedClient{errs: []error{throttled, throttled}, output: allowOutput()}
	p := pluginWith(client)

	verdict, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(1, "some streamed text"))

	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.False(t, verdict.Block)
	assert.Equal(t, 3, client.count())
}

// The retries are bounded: a provider that keeps throttling ends the block as a
// failed one, named as a throttle so it is not counted toward retiring the entry.
func TestStreamBlockStopsRetryingAThrottle(t *testing.T) {
	t.Parallel()
	throttled := throttlingError(t)
	client := &sequencedClient{errs: []error{throttled, throttled, throttled, throttled, throttled, throttled}, output: allowOutput()}
	p := pluginWith(client)

	_, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(1, "some streamed text"))

	var failure *appplugins.ExternalStreamFailure
	require.True(t, errors.As(err, &failure), "got %v", err)
	assert.Equal(t, appplugins.FailureClassAvailability, failure.Class)
	assert.Equal(t, "throttled", failure.Detail)
	assert.LessOrEqual(t, client.count(), 3)
	assert.Greater(t, client.count(), 1)
}

func TestBufferedLegRetriesAThrottle(t *testing.T) {
	t.Parallel()
	throttled := throttlingError(t)
	client := &sequencedClient{errs: []error{throttled}, output: allowOutput()}
	p := pluginWith(client)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings("block"), reqCtx(openAIRequest()), nil)

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	assert.Equal(t, 2, client.count())
}

// One block of a stream must fit the smallest per-second quota of any region
// with room to spare: 25 text units of 1,000 characters, per policy type.
func TestAStreamBlockLeavesHeadroomInTheSmallestRegionalQuota(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	for _, asked := range []int{0, 1 << 20} {
		over := map[string]any{}
		if asked > 0 {
			over["max_accumulated_bytes"] = asked
		}
		ok, opts := p.StreamSettings(streamSettings(over))
		require.True(t, ok)
		assert.LessOrEqual(t, opts.MaxAccumulatedBytes, 10*1000, "a block may use at most 10 of the 25 text units a second")
	}
}
