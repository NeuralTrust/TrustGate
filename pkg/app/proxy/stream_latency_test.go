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

package proxy_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// slowInspector holds every block it is asked about for delay before
// answering. That wait is what the executor charges to the policy's streamed
// span, so it is the guard's hold as the latency fold sees it. On the closing
// segment it writes its span the way the TrustGuard plugin does, its share of
// the hold and a decision; a span without a decision is dropped from the chain.
type slowInspector struct {
	*streamInspectorPlugin
	delay time.Duration
}

func (s *slowInspector) InspectSegment(
	ctx context.Context,
	in appplugins.ExecInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentVerdict, error) {
	if seg.Closing {
		if in.Event != nil {
			in.Event.SetSLatency(seg.Report.GuardLatency)
			appplugins.SetDecisionFromOutcome(in.Event, "allowed")
		}
		return &appplugins.SegmentVerdict{}, nil
	}
	time.Sleep(s.delay)
	return s.streamInspectorPlugin.InspectSegment(ctx, in, seg)
}

type noPricing struct{}

func (noPricing) Resolve(context.Context, string, string) appcatalog.Pricing {
	return appcatalog.Pricing{}
}

func (noPricing) InvalidateCache() {}

// TestForward_StreamGuardHoldIsNotGatewayOverhead pins the latency split of a
// guarded stream on every way it can end. The guard's hold elapses inside the
// provider span, and the metrics fold takes it back out of provider_ms on that
// premise, so the span has to last until the stream ended for the client. A
// stream the head verdict refused kept the span at time to first byte: the
// hold was taken out of the upstream's share instead, clamping it to zero when
// the hold was the longer of the two, and the remainder reported it as gateway
// overhead.
//
// The bounds are one-sided on purpose. provider_ms can only be at least what
// the upstream was made to take, and gateway_ms, the time spent outside the
// attempt and the policies, is a few milliseconds here, so it stays below a
// hold of a hundred. Both fail on a span that stops at the first byte.
func TestForward_StreamGuardHoldIsNotGatewayOverhead(t *testing.T) {
	t.Parallel()
	const drain = 40 * time.Millisecond
	block := &appplugins.SegmentVerdict{Block: true, Type: "guardrail_violation", Message: "blocked"}
	cases := []struct {
		name     string
		ttfb     time.Duration
		hold     time.Duration
		verdict  *appplugins.SegmentVerdict
		blockSeq int
		options  appplugins.StreamOptions
		refused  bool
	}{
		{name: "head block slower to first byte than to verdict", ttfb: 150 * time.Millisecond, hold: 100 * time.Millisecond, verdict: block, refused: true},
		{name: "head block slower to verdict than to first byte", ttfb: 30 * time.Millisecond, hold: 150 * time.Millisecond, verdict: block, refused: true},
		{name: "allowed stream", ttfb: 150 * time.Millisecond, hold: 100 * time.Millisecond, verdict: &appplugins.SegmentVerdict{}},
		{
			name: "cut after the head", ttfb: 150 * time.Millisecond, hold: 100 * time.Millisecond, verdict: block, blockSeq: 2,
			options: appplugins.StreamOptions{HeadChars: 1, MinCharsBetweenEvals: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gatewayID := ids.New[ids.GatewayKind]()
			lines := [][]byte{
				[]byte(`data: {"id":"c","choices":[{"index":0,"delta":{"content":"one"}}]}`), {},
				[]byte(`data: {"id":"c","choices":[{"index":0,"delta":{"content":"two"}}]}`), {},
				[]byte("data: [DONE]"), {},
			}
			// The upstream is still generating after its first byte, which is
			// time the provider spends inside the guard's head drain.
			upstream := func(yield func([]byte, error) bool) {
				time.Sleep(drain)
				for _, l := range lines {
					if !yield(l, nil) {
						return
					}
				}
			}
			invoker := proxymocks.NewProviderInvoker(t)
			invoker.EXPECT().
				InvokeStream(mock.Anything, mock.Anything, mock.Anything).
				RunAndReturn(func(context.Context, *registry.Registry, *infracontext.RequestContext) (*appproxy.ProviderResponse, error) {
					time.Sleep(tc.ttfb)
					return &appproxy.ProviderResponse{StatusCode: http.StatusOK, Stream: upstream}, nil
				}).
				Once()

			p := &slowInspector{
				streamInspectorPlugin: &streamInspectorPlugin{
					stubPlugin: stubPlugin{
						name:   "guardrail",
						stages: []policy.Stage{policy.StagePreResponse},
						result: &appplugins.Result{StatusCode: http.StatusOK},
					},
					verdict:  tc.verdict,
					blockSeq: tc.blockSeq,
					options:  tc.options,
				},
				delay: tc.hold,
			}
			rc := streamingPolicy(t, gatewayID, p)
			fwd := forwarderWithPlugin(t, invoker, p, appproxy.WithStreamCodec(adapter.NewRegistry()))

			rt := trace.New("trace-stream-latency", trace.Metadata{GatewayID: gatewayID.String()})
			ctx := trace.NewContext(context.Background(), rt)
			req := &infracontext.RequestContext{Body: []byte(`{"stream":true}`)}
			start := time.Now()
			res, err := fwd.Forward(ctx, appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: req})
			require.NoError(t, err)
			if tc.refused {
				require.Nil(t, res.Stream, "the head verdict refuses the stream before the first byte")
				assert.Equal(t, http.StatusForbidden, res.StatusCode)
			} else {
				require.NotNil(t, res.Stream)
				for _, lineErr := range res.Stream {
					require.NoError(t, lineErr)
				}
				if res.StreamSettled != nil {
					if settled := res.StreamSettled(); settled != nil {
						<-settled
					}
				}
			}
			end := time.Now()

			resp := &infracontext.ResponseContext{StatusCode: res.StatusCode}
			got := appmetrics.NewBuilder(adapter.NewRegistry(), noPricing{}).
				Build(context.Background(), rt, req, resp, start, end).Latency

			require.NotNil(t, got.ProviderMs)
			assert.GreaterOrEqual(t, *got.ProviderMs, (tc.ttfb + drain).Milliseconds(),
				"the upstream's first byte and the generation the head waited on are the provider's")
			assert.GreaterOrEqual(t, got.PoliciesMs, tc.hold.Milliseconds(), "the hold is charged to the policy")
			assert.Less(t, got.GatewayMs, tc.hold.Milliseconds(), "the hold is not gateway overhead")
			assert.Equal(t, got.TotalMs, *got.ProviderMs+got.PoliciesMs+got.GatewayMs,
				"provider, policies and gateway reconcile against the wall clock, the hold counted once")
		})
	}
}
