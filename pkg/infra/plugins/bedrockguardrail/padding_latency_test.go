// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package bedrockguardrail

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// latencyGuardrail answers after a real delay and gives up when its context
// ends, as a network call does: it is what shows how long a request's own
// chunks take, which a fake that answers at once cannot.
type latencyGuardrail struct {
	delay  time.Duration
	hang   string
	block  string
	calls  atomic.Int32
	answer func() (*bedrockruntime.ApplyGuardrailOutput, error)
}

func (g *latencyGuardrail) ApplyGuardrail(
	ctx context.Context,
	in *bedrockruntime.ApplyGuardrailInput,
	_ ...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	g.calls.Add(1)
	text := textOf(in)
	if g.hang != "" && strings.Contains(text, g.hang) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	select {
	case <-time.After(g.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if g.answer != nil {
		return g.answer()
	}
	if g.block != "" && strings.Contains(text, g.block) {
		return topicBlockedOutput(), nil
	}
	return allowOutput(), nil
}

// quotaGuardrail enforces the documented floor of the smallest-quota regions the
// way AWS does: 25 text units a second with a burst of 25, throttling any call
// that finds fewer units available.
type quotaGuardrail struct {
	latencyGuardrail
	bucket *rate.Limiter
	denied atomic.Int32
	err    error
}

func (g *quotaGuardrail) ApplyGuardrail(
	ctx context.Context,
	in *bedrockruntime.ApplyGuardrailInput,
	opts ...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	if !g.bucket.AllowN(time.Now(), (len(textOf(in))+999)/1000) {
		g.denied.Add(1)
		return nil, g.err
	}
	return g.latencyGuardrail.ApplyGuardrail(ctx, in, opts...)
}

func pluginOver(g guardrailClient) *Plugin {
	p := New(adapter.NewRegistry(), nil)
	p.guardrails = &cachedGuardrailClient{cache: &clientCache{
		build: func(context.Context, awsCredentials) (guardrailClient, error) { return g, nil },
	}}
	return p
}

// A legitimate message of about 60 KB in the region with the smallest quota is
// sent one chunk at a time, spaced under the floor, and is judged: it is never
// refused as oversize and its own calls never throttle it.
func TestALegitimateLongMessageInASmallQuotaRegionPasses(t *testing.T) {
	t.Parallel()
	g := &quotaGuardrail{
		latencyGuardrail: latencyGuardrail{delay: 500 * time.Millisecond},
		bucket:           rate.NewLimiter(25, 25),
		err:              throttlingError(t),
	}
	p := pluginOver(g)
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, benignWords(60000)), nil)
	in.Event = event

	started := time.Now()
	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "allowed", extras.Decision)
	assert.Zero(t, g.denied.Load(), "the request's own calls never exceed the floor")
	assert.Greater(t, extras.ChunkCount, 1)
	assert.Equal(t, extras.ChunkCount, int(g.calls.Load()))
	assert.Less(t, time.Since(started), p.evaluationBudget())
}

// A message above what half of the budget admits is refused before any call, so a
// client cannot pad it until its last chunk is paced to the deadline and fails
// open, even when its harmful part is in that last chunk.
func TestAMessageAboveTheAdmissionCeilingIsRefusedBeforeAnyCall(t *testing.T) {
	t.Parallel()
	text := benignWords(100000) + " HARMFUL-TAIL"
	g := &latencyGuardrail{delay: 500 * time.Millisecond, block: "HARMFUL-TAIL"}
	p := pluginOver(g)
	p.budget = 3 * time.Second
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, text), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "must be refused, never failed open: res=%v err=%v", res, err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Zero(t, g.calls.Load())
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "input", extras.FailureClass)
	assert.Equal(t, appplugins.DetailChunkLimit, extras.FailureDetail)
}

// A text whose quota waits push its estimate over half of the budget, though it
// is within the chunk ceiling, is refused as chunk_budget before any call.
func TestAMessageWhoseQuotaWaitsExceedHalfTheBudgetIsRefusedBeforeAnyCall(t *testing.T) {
	t.Parallel()
	g := &latencyGuardrail{delay: time.Millisecond}
	p := pluginOver(g)
	p.budget, p.reserve = time.Second, 100*time.Millisecond
	text := benignWords(50000)
	require.Equal(t, 3, textchunk.Count(text, chunkSpec))
	require.LessOrEqual(t, 3, p.maxChunks())
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, text), nil)
	in.Event = event

	_, err := p.Execute(context.Background(), in)

	_, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Zero(t, g.calls.Load())
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, appplugins.DetailChunkBudget, extras.FailureDetail)
}

// At the ceiling, a provider that answers each call in less than twice the
// reserve but more than the reserve never runs the budget out: the harmful tail is
// reached and blocked instead of the request failing open.
func TestACeilingTextWithSlowishCallsStillBlocksItsHarmfulTail(t *testing.T) {
	t.Parallel()
	g := &latencyGuardrail{delay: 160 * time.Millisecond, block: "HARMFUL-TAIL"}
	p := pluginOver(g)
	p.budget, p.reserve = time.Second, 100*time.Millisecond
	require.Equal(t, 5, p.maxChunks())
	atCeiling := chunkBytes + (p.maxChunks()-2)*(chunkBytes-chunkOverlap)
	text := benignWords(atCeiling+19000) + " HARMFUL-TAIL"
	require.Equal(t, 5, textchunk.Count(text, chunkSpec))
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, text), nil)

	res, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "must block, never fail open: res=%v err=%v", res, err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.EqualValues(t, 5, g.calls.Load())
}

// The request's own calls are spaced under the floor, so a throttle AWS still
// returns on a request of several chunks is other traffic: availability.
func TestAThrottleOnASpacedMultiChunkRequestIsAvailability(t *testing.T) {
	t.Parallel()
	throttled := throttlingError(t)
	p := pluginOver(guardrailFunc(func(context.Context) error { return throttled }))
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, benignWords(60000)), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Greater(t, extras.ChunkCount, 1)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, appplugins.DetailThrottled, extras.FailureDetail)
	assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
}

func TestTheLargestUSRegionsUseTheirLargerFloor(t *testing.T) {
	t.Parallel()
	text := benignWords(100000)
	chunks := textchunk.Split(text, chunkSpec)
	assert.Equal(t, regionQuota{50, 200}, floorFor("us-east-1"))
	assert.Equal(t, regionQuota{50, 200}, floorFor("us-west-2"))
	assert.Equal(t, regionQuota{25, 25}, floorFor("eu-west-3"))
	assert.Equal(t, regionQuota{50, 200}, floorFor(""))
	small, large := estimateDuration(chunks, floorFor("eu-west-3"), callReserve), estimateDuration(chunks, floorFor("us-east-1"), callReserve)
	assert.Equal(t, time.Duration(len(chunks))*callReserve, large, "105 units fit the 200-unit burst, so there is no wait")
	assert.Equal(t, large, small, "the quota refills more than a chunk uses while a call runs, so the floor adds no wait")

	g := &latencyGuardrail{delay: 20 * time.Millisecond}
	p := pluginOver(g)
	started := time.Now()
	res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, text), nil))
	assertPassThrough(t, res, err)
	assert.Less(t, time.Since(started), time.Second, "no spacing inside the burst")
}

// The estimate admitted the request, so a chunk that hangs after the first one is
// the provider being slower than that estimate: availability, never input.
func TestAChunkOfAnAdmittedRequestThatHangsFailsOpen(t *testing.T) {
	t.Parallel()
	// The marker sits in the second chunk, which waits behind the first.
	words := benignWords(40000)
	text := words[:30000] + " HANG-HERE " + words[30000:]
	g := &latencyGuardrail{delay: 10 * time.Millisecond, hang: "HANG-HERE"}
	p := pluginOver(g)
	p.budget = 4 * time.Second
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, text), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
	assert.NotEqual(t, appplugins.DetailChunkBudget, extras.FailureDetail)
}

// The provider being slow on a chunk of the first round is its own doing.
func TestASlowChunkOfTheFirstRoundIsAvailability(t *testing.T) {
	t.Parallel()
	text := "HANG-HERE " + benignWords(15000)
	g := &latencyGuardrail{delay: 10 * time.Millisecond, hang: "HANG-HERE"}
	p := pluginOver(g)
	p.budget = 2 * time.Second
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, text), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
}

// The first chunk of an admitted two-chunk request takes nearly the whole budget,
// so the second is not started for lack of reserve. The provider was slower than
// the estimate, which is not the request's doing.
func TestASlowFirstChunkOfAnAdmittedRequestFailsOpen(t *testing.T) {
	t.Parallel()
	g := &latencyGuardrail{delay: 2850 * time.Millisecond}
	p := pluginOver(g)
	p.budget = 3 * time.Second
	text := benignWords(30000)
	require.Equal(t, 2, textchunk.Count(text, chunkSpec))
	require.LessOrEqual(t, estimateDuration(textchunk.Split(text, chunkSpec), floorFor("eu-west-3"), p.callReserveFor()), p.budget/2)
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, text), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
	assert.EqualValues(t, 1, g.calls.Load(), "the second chunk was never started")
}

// A provider that hangs on the third chunk of an admitted request fails open.
func TestAHangOnTheThirdChunkOfAnAdmittedRequestFailsOpen(t *testing.T) {
	t.Parallel()
	words := benignWords(60000)
	text := words[:50000] + " HANG-HERE " + words[50000:]
	require.Equal(t, 3, textchunk.Count(text, chunkSpec))
	g := &latencyGuardrail{delay: 10 * time.Millisecond, hang: "HANG-HERE"}
	p := pluginOver(g)
	p.budget, p.reserve = 3*time.Second, 300*time.Millisecond
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, text), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
}

// A legitimate message of 84 KB and one of 100 KB, in the region with the
// smallest quota, are judged and never refused. The budget is far above what the
// spaced calls need, so a slow runner cannot cut a chunk.
func TestLongLegitimateMessagesInASmallQuotaRegionPassInEnforce(t *testing.T) {
	t.Parallel()
	for _, size := range []int{84000, 100000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			t.Parallel()
			g := &quotaGuardrail{
				latencyGuardrail: latencyGuardrail{delay: 100 * time.Millisecond},
				bucket:           rate.NewLimiter(25, 25),
				err:              throttlingError(t),
			}
			p := pluginOver(g)
			p.budget = time.Minute
			event, span := eventFor(t)
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, benignWords(size)), nil)
			in.Event = event

			res, err := p.Execute(context.Background(), in)

			assertPassThrough(t, res, err)
			extras, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, "allowed", extras.Decision)
			assert.Zero(t, g.denied.Load())
			assert.Equal(t, extras.ChunkCount, int(g.calls.Load()))
		})
	}
}

// The ceiling is the same in every region, and the estimate never exceeds the
// headroom up to it: a text of maxBufferedChunks chunks (203,416 bytes) is judged,
// one byte more is refused as chunk_limit before any call.
func TestTheCeilingIsTheSameInEveryRegion(t *testing.T) {
	t.Parallel()
	atCeiling := chunkBytes + (maxBufferedChunks-1)*(chunkBytes-chunkOverlap)
	require.Equal(t, 10, maxBufferedChunks)
	require.Equal(t, maxBufferedChunks, textchunk.Count(strings.Repeat("a", atCeiling), chunkSpec))
	require.Equal(t, maxBufferedChunks+1, textchunk.Count(strings.Repeat("a", atCeiling+1), chunkSpec))
	for _, region := range []string{"", "eu-west-3", "us-east-1", "us-west-2"} {
		t.Run(region, func(t *testing.T) {
			t.Parallel()
			chunks := textchunk.Split(strings.Repeat("a", atCeiling), chunkSpec)
			assert.Equal(t, bufferedBudget/2, estimateDuration(chunks, floorFor(region), callReserve), "the largest text just fits half of the budget")

			g := &latencyGuardrail{delay: time.Millisecond}
			full := pluginOver(&latencyGuardrail{delay: time.Millisecond})
			res, err := full.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce,
				settingsIn(regionOrDefault(region)), chatRequestOf(t, strings.Repeat("a", atCeiling)), nil))
			assertPassThrough(t, res, err)

			p := pluginOver(g)
			event, span := eventFor(t)
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn(regionOrDefault(region)), chatRequestOf(t, strings.Repeat("a", atCeiling+1)), nil)
			in.Event = event
			_, err = p.Execute(context.Background(), in)

			pe, ok := appplugins.AsPluginError(err)
			require.True(t, ok, "got %v", err)
			assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
			assert.Zero(t, g.calls.Load(), "refused before any call")
			extras, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, appplugins.DetailChunkLimit, extras.FailureDetail)
		})
	}
}

func regionOrDefault(region string) string {
	if region == "" {
		return defaultRegion
	}
	return region
}

// A provider that hangs on the first chunk is cut by the call's own timeout, not
// by the evaluation's budget: the request fails open after about one call.
func TestAHangFailsOpenAtTheCallTimeoutNotTheBudget(t *testing.T) {
	t.Parallel()
	g := &latencyGuardrail{delay: 10 * time.Millisecond, hang: "HANG-HERE"}
	p := pluginOver(g)
	p.callTimeout = 400 * time.Millisecond
	require.Equal(t, bufferedBudget, p.evaluationBudget())
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, "HANG-HERE "+benignWords(15000)), nil)
	in.Event = event

	started := time.Now()
	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	assert.Less(t, time.Since(started), 3*time.Second, "far below the evaluation budget")
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
	assert.Equal(t, "availability", extras.FailureClass)
}
