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

package trustguard

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func blocksOf(calls []GuardRequest) (seqs, blocks []int) {
	for _, c := range calls {
		seqs = append(seqs, c.Attributes.Stream.Seq)
		blocks = append(blocks, c.Attributes.Stream.Block)
	}
	return seqs, blocks
}

// The block is the position among the evaluates that were sent, not the
// gateway's sequence number. A response whose leading segments were skipped as
// empty never reaches a seq 1, which is exactly the case the position exists
// for.
func TestInspectSegmentBlockCountsOnlyTheEvaluatesThatWereSent(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	ctx := segmentTraceContext()
	in := segmentInput(t, streamingSettings(nil))

	for _, seg := range []appplugins.StreamSegment{
		{Seq: 1},                        // nothing produced yet: skipped
		{Seq: 2},                        // skipped
		{Seq: 3, Accumulated: "Hel"},    // first evaluate sent
		{Seq: 4, Accumulated: "Hello"},  // second
		{Seq: 5},                        // skipped in the middle
		{Seq: 6, Accumulated: "Hello!"}, // third: seq 6, block 3
	} {
		_, err := p.InspectSegment(ctx, in, seg)
		require.NoError(t, err)
	}

	seqs, blocks := blocksOf(g.calls())
	assert.Equal(t, []int{3, 4, 6}, seqs, "seq is the gateway's own count and keeps its gaps")
	assert.Equal(t, []int{1, 2, 3}, blocks, "block is dense over what was sent")
}

// A call that fails on the wire was still sent and keeps its place; the next
// one is the next position.
func TestInspectSegmentBlockCountsAFailedCall(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{status: http.StatusInternalServerError}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	ctx := segmentTraceContext()
	in := segmentInput(t, streamingSettings(nil))

	_, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 1, Accumulated: "a"})
	require.NoError(t, err)
	g.mu.Lock()
	g.status = 0
	g.response = GuardResponse{Status: statusAllow}
	g.mu.Unlock()
	_, err = p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 2, Accumulated: "ab"})
	require.NoError(t, err)

	_, blocks := blocksOf(g.calls())
	assert.Equal(t, []int{1, 2}, blocks)
}

// A stream that stops being inspected after repeated failures sends nothing, so
// it counts nothing either.
func TestInspectSegmentBlockDoesNotAdvanceWhileTheStreamIsRetired(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{status: http.StatusInternalServerError}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	ctx := segmentTraceContext()
	in := segmentInput(t, streamingSettings(nil))

	for seq := 1; seq <= streamRetireAfter+3; seq++ {
		_, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: seq, Accumulated: "text"})
		require.NoError(t, err)
	}
	calls := g.calls()
	require.Len(t, calls, streamRetireAfter, "after the retirement no evaluate is sent")
	_, blocks := blocksOf(calls)
	assert.Equal(t, []int{1, 2, 3}, blocks)
}

func TestInspectSegmentBlocksAreCountedPerStream(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	in := segmentInput(t, streamingSettings(nil))
	a := trace.NewContext(context.Background(), trace.New("trace-a", trace.Metadata{}))
	b := trace.NewContext(context.Background(), trace.New("trace-b", trace.Metadata{}))

	for _, step := range []struct {
		ctx context.Context
		seq int
	}{{a, 1}, {b, 1}, {a, 2}, {b, 2}, {a, 3}} {
		_, err := p.InspectSegment(step.ctx, in, appplugins.StreamSegment{Seq: step.seq, Accumulated: "x"})
		require.NoError(t, err)
	}

	byStream := map[string][]int{}
	for _, c := range g.calls() {
		byStream[c.Attributes.Stream.ID] = append(byStream[c.Attributes.Stream.ID], c.Attributes.Stream.Block)
	}
	assert.Equal(t, []int{1, 2, 3}, byStream["trace-a"+streamIDSeparator+legResponse])
	assert.Equal(t, []int{1, 2}, byStream["trace-b"+streamIDSeparator+legResponse])
}

// The counter lives for one stream. The closing segment takes it out, so an id
// that is reused, or a leak, cannot make the next stream start at 7.
func TestInspectSegmentClosingForgetsTheStreamPosition(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	ctx := segmentTraceContext()
	in := segmentInput(t, streamingSettings(nil))

	for seq := 1; seq <= 3; seq++ {
		_, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: seq, Accumulated: "x"})
		require.NoError(t, err)
	}
	key, ok := streamFailureKey(ctx, in, appplugins.StreamSegment{})
	require.True(t, ok)
	_, held := p.streamBlocks.Load(key)
	require.True(t, held, "the counter is held while the stream runs")

	_, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 4, Closing: true})
	require.NoError(t, err)
	_, held = p.streamBlocks.Load(key)
	assert.False(t, held, "and gone once the stream closed")

	_, err = p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 1, Accumulated: "next"})
	require.NoError(t, err)
	calls := g.calls()
	assert.Equal(t, 1, calls[len(calls)-1].Attributes.Stream.Block, "a new stream starts over")
}

// A stream with no identity has no envelope at all, so there is nothing to
// number it under.
func TestInspectSegmentWithoutAStreamIDSendsNoBlock(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	in := segmentInput(t, streamingSettings(nil))
	for seq := 1; seq <= 2; seq++ {
		_, err := p.InspectSegment(context.Background(), in, appplugins.StreamSegment{Seq: seq, Accumulated: "x"})
		require.NoError(t, err)
	}
	for _, c := range g.calls() {
		assert.Nil(t, c.Attributes.Stream)
	}
	n := 0
	p.streamBlocks.Range(func(_, _ any) bool { n++; return true })
	assert.Zero(t, n, "no identity, no counter to leak")
}

func TestSweepStreamBlocksDropsCountersAClosingNeverReached(t *testing.T) {
	t.Parallel()

	p := newTestPlugin(t, adapter.NewRegistry(), "http://127.0.0.1:1")
	now := time.Now()
	p.streamBlocks.Store("old", &streamPosition{sent: 3, at: now.Add(-streamFailureTTL - time.Second)})
	p.streamBlocks.Store("fresh", &streamPosition{sent: 1, at: now})

	p.sweepStreamBlocks(now)

	_, old := p.streamBlocks.Load("old")
	_, fresh := p.streamBlocks.Load("fresh")
	assert.False(t, old)
	assert.True(t, fresh)
}

// The field rides inside attributes.stream, where an engine that predates it
// ignores it (attributes are free-form), and is left off when unknown.
func TestGuardStreamBlockWireShape(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(GuardRequest{Attributes: GuardAttributes{Stream: &GuardStream{ID: "t:response", Seq: 5, Block: 2}}})
	require.NoError(t, err)
	var wire map[string]any
	require.NoError(t, json.Unmarshal(raw, &wire))
	assert.NotContains(t, wire, "block", "never at the root, where the engine's strict decoder would reject it")
	stream := wire["attributes"].(map[string]any)["stream"].(map[string]any)
	assert.EqualValues(t, 2, stream["block"])
	assert.EqualValues(t, 5, stream["seq"])

	raw, err = json.Marshal(GuardStream{ID: "t:response", Seq: 1})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "block", "an unknown position is omitted, not sent as 0")
}

// Gate and Guard bill independently. A request spends one Gate unit when the
// forwarder charges it, however many evaluates the plugin then makes; each
// evaluate is one call to the guard, which spends one Guard unit on its own side.
func TestAGateRequestSpendsOneGateUnitAndOneGuardUnitPerEvaluate(t *testing.T) {
	t.Parallel()

	gw := ids.New[ids.GatewayKind]()
	resolver := stubGateResolver{resolved: ratelimitapp.Resolved{
		Subject: "tenant-1", Limits: ratelimitdomain.Limits{BurstPerMin: 100, QuotaPerMonth: 100},
	}}
	backend := &recordingBackend{}
	meter := ratelimitapp.NewMeter(resolver, backend, ratelimitapp.Options{SyncInterval: time.Hour, DisableKick: true}, nil)

	g := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, g).URL)

	require.NoError(t, meter.Check(context.Background(), gw), "the forwarder charges the request once")
	for _, stage := range []policy.Stage{policy.StagePreRequest, policy.StagePreResponse} {
		resp := &infracontext.ResponseContext{Body: openAIResponseBody()}
		_, err := p.Execute(context.Background(), execInput(stage, policy.ModeEnforce, settings("request_response"), requestContext(), resp))
		require.NoError(t, err)
	}

	assert.Equal(t, 2, g.count(), "two evaluates reached the guard: two Guard units, billed there")
	require.NoError(t, meter.SyncNow(context.Background()))
	assert.EqualValues(t, 1, backend.delta(ratelimitdomain.KindQuota), "and exactly one Gate unit")
	assert.EqualValues(t, 1, backend.delta(ratelimitdomain.KindBurst))
}

type stubGateResolver struct{ resolved ratelimitapp.Resolved }

func (r stubGateResolver) Resolve(context.Context, ids.GatewayID) (ratelimitapp.Resolved, error) {
	return r.resolved, nil
}

// recordingBackend is the Redis a Gate meter would sync to, reduced to the
// deltas it was asked to apply.
type recordingBackend struct {
	mu     sync.Mutex
	deltas map[ratelimitdomain.CounterKind]int64
}

func (b *recordingBackend) Sync(_ context.Context, items []ratelimitdomain.SyncItem) ([]ratelimitdomain.SyncResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.deltas == nil {
		b.deltas = map[ratelimitdomain.CounterKind]int64{}
	}
	out := make([]ratelimitdomain.SyncResult, len(items))
	for i, item := range items {
		totals := make([]int64, len(item.Bumps))
		for j, bump := range item.Bumps {
			b.deltas[bump.Kind] += bump.Delta
			totals[j] = b.deltas[bump.Kind]
		}
		out[i] = ratelimitdomain.SyncResult{Totals: totals}
	}
	return out, nil
}

func (b *recordingBackend) delta(kind ratelimitdomain.CounterKind) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.deltas[kind]
}
