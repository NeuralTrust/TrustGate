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

// A message whose spaced waits and calls cannot fit the budget is refused before
// any call, so a client cannot pad it until its last chunk is paced to the
// deadline and fails open, even when its harmful part is in that last chunk.
func TestAMessageThatCannotFitTheBudgetIsRefusedBeforeAnyCall(t *testing.T) {
	t.Parallel()
	text := benignWords(252000) + " HARMFUL-TAIL"
	g := &latencyGuardrail{delay: 500 * time.Millisecond, block: "HARMFUL-TAIL"}
	p := pluginOver(g)
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
	assert.Equal(t, appplugins.DetailChunkBudget, extras.FailureDetail)
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
	small, large := estimateDuration(chunks, floorFor("eu-west-3")), estimateDuration(chunks, floorFor("us-east-1"))
	assert.Greater(t, small, large, "105 units fit the 200-unit burst, so there is no wait")
	assert.Equal(t, time.Duration(len(chunks))*callReserve, large)

	g := &latencyGuardrail{delay: 20 * time.Millisecond}
	p := pluginOver(g)
	started := time.Now()
	res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, text), nil))
	assertPassThrough(t, res, err)
	assert.Less(t, time.Since(started), time.Second, "no spacing inside the burst")
}

// The chunks after the first round wait for this request's own earlier chunks. A
// chunk that is cut by the evaluation's budget after waiting was kept from
// finishing by the request's size, so it is input, not an outage.
func TestAChunkCutByTheBudgetAfterWaitingIsInputInEnforce(t *testing.T) {
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

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got res=%v err=%v", res, err)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "input", extras.FailureClass)
	assert.Equal(t, appplugins.DetailChunkBudget, extras.FailureDetail)
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
