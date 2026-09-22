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
	"errors"
	"iter"
	"sync/atomic"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type stubPlugin struct {
	name   string
	stages []policy.Stage
	result *appplugins.Result
	err    error
	ran    chan policy.Stage
	seen   chan appplugins.ExecInput
}

func (s *stubPlugin) Name() string                    { return s.name }
func (s *stubPlugin) MandatoryStages() []policy.Stage { return s.stages }
func (s *stubPlugin) SupportedStages() []policy.Stage { return s.stages }
func (s *stubPlugin) SupportedModes() []policy.Mode   { return []policy.Mode{policy.ModeEnforce} }
func (s *stubPlugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}
func (s *stubPlugin) ValidateConfig(map[string]any) error { return nil }
func (s *stubPlugin) MutatesRequestBody() bool            { return false }
func (s *stubPlugin) MutatesResponseBody() bool           { return false }
func (s *stubPlugin) MutatesMetadata() bool               { return false }
func (s *stubPlugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if s.ran != nil {
		s.ran <- in.Stage
	}
	if s.seen != nil {
		s.seen <- in
	}
	return s.result, s.err
}

func forwarderWithPlugin(
	t *testing.T,
	invoker appproxy.ProviderInvoker,
	p appplugins.Plugin,
	opts ...appproxy.ForwarderOption,
) appproxy.Forwarder {
	t.Helper()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(p))
	exec := appplugins.NewExecutor(reg, newTestLogger())
	mgr := cache.NewTTLMapManager(time.Minute)
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil),
		newPermissiveCache(t), mgr, invoker, exec, nil, approuting.NewResolver(), nil, nil, nil, newTestLogger(),
		opts...,
	)
}

func TestForward_PreRequestPluginErrorShortCircuits(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "pol",
		Slug:     "rate_limiter",
		Enabled:  true,
		Priority: 1,
	}}

	invoker := proxymocks.NewProviderInvoker(t)
	// Invoke must never be called on a rejection.

	p := &stubPlugin{
		name:   "rate_limiter",
		stages: []policy.Stage{policy.StagePreRequest},
		err:    &appplugins.PluginError{StatusCode: 429, Message: "too many", Headers: map[string][]string{"Retry-After": {"60"}}},
	}
	fwd := forwarderWithPlugin(t, invoker, p)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, 429, res.StatusCode)
	assert.Equal(t, []string{"60"}, res.Headers["Retry-After"])
	assert.Contains(t, string(res.Body), "too many")
}

func TestForward_PreRequestStopUpstreamServesCache(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "pol",
		Slug:     "semantic_cache",
		Enabled:  true,
		Priority: 1,
	}}

	invoker := proxymocks.NewProviderInvoker(t)

	p := &stubPlugin{
		name:   "semantic_cache",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &appplugins.Result{StatusCode: 200, Body: []byte("cached"), StopUpstream: true, Headers: map[string][]string{"X-Cache-Status": {"HIT"}}},
	}
	fwd := forwarderWithPlugin(t, invoker, p)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "cached", string(res.Body))
	assert.Equal(t, []string{"HIT"}, res.Headers["X-Cache-Status"])
}

func TestForward_PreRequestSeesResolvedProvider(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "pol",
		Slug:     "token_rate_limiter",
		Enabled:  true,
		Priority: 1,
		Stages:   []policy.Stage{policy.StagePreRequest},
	}}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	seen := make(chan appplugins.ExecInput, 1)
	p := &stubPlugin{
		name:   "token_rate_limiter",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &appplugins.Result{StatusCode: 200},
		seen:   seen,
	}
	fwd := forwarderWithPlugin(t, invoker, p)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)

	select {
	case in := <-seen:
		require.NotNil(t, in.Request)
		assert.Equal(t, "openai", in.Request.Provider)
	case <-time.After(2 * time.Second):
		t.Fatal("pre_request plugin did not run")
	}
}

func TestForward_PreResponsePluginRejectsStream(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "pol",
		Slug:     "guardrail",
		Enabled:  true,
		Priority: 1,
	}}

	// The stream is drained internally for cleanup, so guard the shared flag and
	// only assert that no bytes are surfaced to the client (res.Stream is nil).
	stream := func(yield func([]byte, error) bool) {
		yield([]byte("data: leak"), nil)
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Stream: stream}, nil).
		Once()

	p := &stubPlugin{
		name:   "guardrail",
		stages: []policy.Stage{policy.StagePreResponse},
		err:    &appplugins.PluginError{StatusCode: 451, Message: "blocked"},
	}
	fwd := forwarderWithPlugin(t, invoker, p)

	req := &infracontext.RequestContext{Body: []byte(`{"stream":true}`)}
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   req,
	})
	require.NoError(t, err)
	// A pre_response rejection must short-circuit the streaming success path:
	// the client receives the rejection body, not the upstream stream.
	assert.Nil(t, res.Stream, "rejected stream must not be relayed to the client")
	assert.Equal(t, 451, res.StatusCode)
	assert.Contains(t, string(res.Body), "blocked")
}

// streamInspectorPlugin is a plugin that opted into per-segment inspection and
// answers StreamSettings from the policy, which is what makes StreamPlan yield
// a head gate.
type streamInspectorPlugin struct {
	stubPlugin
	verdict *appplugins.SegmentVerdict
	// blockSeq places the verdict on one block rather than on every one, which
	// is what tells the two cut regimes apart: block 1 is the head.
	blockSeq int
	options  appplugins.StreamOptions
	postSeen chan appplugins.ExecInput
}

func (s *streamInspectorPlugin) Execute(
	ctx context.Context,
	in appplugins.ExecInput,
) (*appplugins.Result, error) {
	if in.Stage == policy.StagePostResponse && s.postSeen != nil {
		s.postSeen <- in
	}
	return s.stubPlugin.Execute(ctx, in)
}

func (s *streamInspectorPlugin) InspectSegment(
	_ context.Context,
	_ appplugins.ExecInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentVerdict, error) {
	if s.blockSeq > 0 && seg.Seq != s.blockSeq {
		return &appplugins.SegmentVerdict{}, nil
	}
	return s.verdict, nil
}

func (s *streamInspectorPlugin) StreamSettings(settings map[string]any) (bool, appplugins.StreamOptions) {
	enabled, _ := settings["enabled"].(bool)
	return enabled, s.options
}

// streamingPolicy wires a consumer with the precompiled plan the forwarder
// reads. StreamPlan is a plan predicate, and the consumer plan is never nil in
// production (app/consumer/consumer_data.go).
func streamingPolicy(t *testing.T, gatewayID ids.GatewayID, p appplugins.Plugin) *appconsumer.RoutableConsumer {
	t.Helper()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "openai"))
	rc.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "pol",
		Slug:     p.Name(),
		Enabled:  true,
		Priority: 1,
		Settings: map[string]any{"enabled": true},
	}}
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(p))
	rc.PolicyPlan = appplugins.NewStagePlan(reg, rc.Policies, newTestLogger())
	return rc
}

func sseLinesStream(lines [][]byte) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, l := range lines {
			if !yield(l, nil) {
				return
			}
		}
	}
}

// TestForward_HeadGateBlockIsARealStatus is the property the whole slice exists
// for: the head verdict lands before finalizeStream returns, so the rejection
// is a status code and a body rather than a terminator, and not one byte of
// the upstream response is relayed.
func TestForward_HeadGateBlockIsARealStatus(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()

	lines := [][]byte{
		[]byte(`data: {"id":"c","choices":[{"index":0,"delta":{"content":"secret"}}]}`), {},
		[]byte("data: [DONE]"), {},
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Stream: sseLinesStream(lines)}, nil).
		Once()

	p := &streamInspectorPlugin{
		stubPlugin: stubPlugin{
			name:   "guardrail",
			stages: []policy.Stage{policy.StagePreResponse},
			result: &appplugins.Result{StatusCode: 200},
		},
		verdict: &appplugins.SegmentVerdict{Block: true, Type: "guardrail_violation", Message: "blocked in the head"},
	}
	rc := streamingPolicy(t, gatewayID, p)
	fwd := forwarderWithPlugin(t, invoker, p, appproxy.WithStreamCodec(adapter.NewRegistry()))

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: []byte(`{"stream":true}`)},
	})
	require.NoError(t, err)
	assert.Nil(t, res.Stream, "a head-gate block must write nothing")
	assert.Equal(t, 403, res.StatusCode)
	assert.Contains(t, string(res.Body), "blocked in the head")
	assert.NotContains(t, string(res.Body), "secret")
}

// TestForward_StreamIsUntouchedWithoutAnInspector is the wiring AC. A policy
// that never opted in must see the stream it sees today, byte for byte.
func TestForward_StreamIsUntouchedWithoutAnInspector(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()

	lines := [][]byte{
		[]byte(`data: {"id":"c","choices":[{"index":0,"delta":{"content":"hi"}}]}`), {},
		[]byte("data: [DONE]"), {},
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Stream: sseLinesStream(lines)}, nil).
		Once()

	p := &stubPlugin{
		name:   "guardrail",
		stages: []policy.Stage{policy.StagePreResponse},
		result: &appplugins.Result{StatusCode: 200},
	}
	rc := streamingPolicy(t, gatewayID, p)
	fwd := forwarderWithPlugin(t, invoker, p, appproxy.WithStreamCodec(adapter.NewRegistry()))

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: []byte(`{"stream":true}`)},
	})
	require.NoError(t, err)
	require.NotNil(t, res.Stream)

	var got [][]byte
	for line, lineErr := range res.Stream {
		require.NoError(t, lineErr)
		got = append(got, line)
	}
	assert.Equal(t, lines, got)
}

func TestForward_PreResponseInfrastructureErrorBlocksEnforce(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "pol",
		Slug:     "guardrail",
		Enabled:  true,
		Priority: 1,
		Stages:   []policy.Stage{policy.StagePreResponse},
		Mode:     policy.ModeEnforce,
	}}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("unsafe upstream body")}, nil).
		Once()

	p := &stubPlugin{
		name:   "guardrail",
		stages: []policy.Stage{policy.StagePreResponse},
		err:    errors.New("provider policy backend down"),
	}
	fwd := forwarderWithPlugin(t, invoker, p)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, 502, res.StatusCode)
	assert.NotContains(t, string(res.Body), "unsafe upstream body")
	assert.Contains(t, string(res.Body), "pre_response plugin stage failed")
}

func TestForward_PostResponseRunsAfterSyncInvoke(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "pol",
		Slug:     "token_rate_limiter",
		Enabled:  true,
		Priority: 1,
	}}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	ran := make(chan policy.Stage, 4)
	p := &stubPlugin{
		name:   "token_rate_limiter",
		stages: []policy.Stage{policy.StagePreRequest, policy.StagePostResponse},
		result: &appplugins.Result{StatusCode: 200},
		ran:    ran,
	}
	fwd := forwarderWithPlugin(t, invoker, p)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)

	stages := collectStages(t, ran, 2)
	assert.Contains(t, stages, policy.StagePreRequest)
	assert.Contains(t, stages, policy.StagePostResponse)
}

// capturePlugin records the ExecInput it observed for a given stage so tests can
// assert what PostResponse saw (accumulated body, usage metadata).
type capturePlugin struct {
	name    string
	stages  []policy.Stage
	seen    chan appplugins.ExecInput
	observe func(context.Context)
}

func (c *capturePlugin) Name() string                    { return c.name }
func (c *capturePlugin) MandatoryStages() []policy.Stage { return c.stages }
func (c *capturePlugin) SupportedStages() []policy.Stage { return c.stages }
func (c *capturePlugin) SupportedModes() []policy.Mode   { return []policy.Mode{policy.ModeEnforce} }
func (c *capturePlugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}
func (c *capturePlugin) ValidateConfig(map[string]any) error { return nil }
func (c *capturePlugin) MutatesRequestBody() bool            { return false }
func (c *capturePlugin) MutatesResponseBody() bool           { return false }
func (c *capturePlugin) MutatesMetadata() bool               { return false }
func (c *capturePlugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if in.Stage == policy.StagePostResponse && c.seen != nil {
		if c.observe != nil {
			c.observe(ctx)
		}
		c.seen <- in
	}
	return &appplugins.Result{StatusCode: 200}, nil
}

func TestForward_PostResponseRunsAfterStreamDrained(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "pol",
		Slug:     "token_rate_limiter",
		Enabled:  true,
		Priority: 1,
	}}

	streamLines := [][]byte{[]byte("data: {\"a\":1}"), {}, []byte("data: {\"b\":2}")}
	stream := func(yield func([]byte, error) bool) {
		for _, l := range streamLines {
			if !yield(l, nil) {
				return
			}
		}
	}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Stream: stream}, nil).
		Once()

	ctx := requestmeta.NewContext(context.Background(), "203.0.113.42", map[string][]string{"User-Agent": {"client/1.0"}})
	principal := &identity.Principal{Subject: "end-user", Claims: map[string]any{"email": "user@example.test"}}
	ctx, cancel := context.WithCancel(identity.WithPrincipal(ctx, principal))
	defer cancel()
	seen := make(chan appplugins.ExecInput, 1)
	p := &capturePlugin{
		name:   "token_rate_limiter",
		stages: []policy.Stage{policy.StagePreRequest, policy.StagePostResponse},
		seen:   seen,
		observe: func(postCtx context.Context) {
			assert.NoError(t, postCtx.Err())
			_, bounded := postCtx.Deadline()
			assert.True(t, bounded)
			assert.Equal(t, principal, identity.PrincipalFromContext(postCtx))
			assert.Equal(t, requestmeta.FromContext(ctx), requestmeta.FromContext(postCtx))
		},
	}
	fwd := forwarderWithPlugin(t, invoker, p)

	req := &infracontext.RequestContext{Body: []byte(`{"stream":true}`)}
	res, err := fwd.Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   req,
	})
	require.NoError(t, err)
	require.NotNil(t, res.Stream)

	// PostResponse must not fire until the consumer drains the stream.
	select {
	case <-seen:
		t.Fatal("PostResponse fired before the stream was drained")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	var relayed []string
	for line, lineErr := range res.Stream {
		require.NoError(t, lineErr)
		relayed = append(relayed, string(line))
	}
	assert.Equal(t, []string{"data: {\"a\":1}", "", "data: {\"b\":2}"}, relayed,
		"every upstream line (including the blank separator) must reach the client verbatim")

	select {
	case in := <-seen:
		assert.Equal(t, []byte("data: {\"a\":1}\ndata: {\"b\":2}\n"), in.Response.Body,
			"PostResponse should observe the accumulated body without blank separators")
	case <-time.After(2 * time.Second):
		t.Fatal("PostResponse never ran after the stream drained")
	}
}

func TestForward_PostResponseSkippedOnStreamAbort(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "pol",
		Slug:     "token_rate_limiter",
		Enabled:  true,
		Priority: 1,
	}}

	stream := func(yield func([]byte, error) bool) {
		for i := 0; i < 5; i++ {
			if !yield([]byte("data: chunk"), nil) {
				return
			}
		}
	}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Stream: stream}, nil).
		Once()

	seen := make(chan appplugins.ExecInput, 1)
	p := &capturePlugin{
		name:   "token_rate_limiter",
		stages: []policy.Stage{policy.StagePreRequest, policy.StagePostResponse},
		seen:   seen,
	}
	fwd := forwarderWithPlugin(t, invoker, p)

	req := &infracontext.RequestContext{Body: []byte(`{"stream":true}`)}
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   req,
	})
	require.NoError(t, err)
	require.NotNil(t, res.Stream)

	// Consumer aborts after the first line (simulating a client disconnect).
	for range res.Stream {
		break
	}

	select {
	case <-seen:
		t.Fatal("PostResponse must not run when the stream is aborted mid-flight")
	case <-time.After(100 * time.Millisecond):
	}
}

func collectStages(t *testing.T, ch chan policy.Stage, n int) []policy.Stage {
	t.Helper()
	var out []policy.Stage
	timeout := time.After(2 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case s := <-ch:
			out = append(out, s)
		case <-timeout:
			t.Fatalf("timed out waiting for stage %d/%d", i+1, n)
		}
	}
	return out
}

// TestForward_MidStreamCutEndsOnATerminatorAndDrainsTheUpstream is the other
// regime end to end. Past the head the status is committed, so the rejection is
// a 200 that ends on a content-filter terminator — and the upstream it
// abandoned is still read to the end in the background, because usage rides the
// last chunk and observeChunk sees it when the line is read, not when it is
// released. Without that wiring a cut stream is charged nothing at all.
func TestForward_MidStreamCutEndsOnATerminatorAndDrainsTheUpstream(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()

	lines := [][]byte{
		[]byte(`data: {"id":"c","choices":[{"index":0,"delta":{"content":"one"}}]}`), {},
		[]byte(`data: {"id":"c","choices":[{"index":0,"delta":{"content":"two"}}]}`), {},
		[]byte(`data: {"id":"c","choices":[{"index":0,"delta":{"content":"three"}}]}`), {},
		[]byte(`data: {"id":"c","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`), {},
		[]byte("data: [DONE]"), {},
	}
	var pulled atomic.Int64
	counted := func(yield func([]byte, error) bool) {
		for _, l := range lines {
			pulled.Add(1)
			if !yield(l, nil) {
				return
			}
		}
	}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Stream: counted}, nil).
		Once()

	p := &streamInspectorPlugin{
		stubPlugin: stubPlugin{
			name:   "guardrail",
			stages: []policy.Stage{policy.StagePreResponse},
			result: &appplugins.Result{StatusCode: 200},
		},
		verdict:  &appplugins.SegmentVerdict{Block: true, Type: "guardrail_violation", Message: "blocked mid-stream"},
		blockSeq: 2,
		options:  appplugins.StreamOptions{HeadChars: 1, MinCharsBetweenEvals: 1},
	}
	rc := streamingPolicy(t, gatewayID, p)
	fwd := forwarderWithPlugin(t, invoker, p, appproxy.WithStreamCodec(adapter.NewRegistry()))

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: []byte(`{"stream":true}`)},
	})
	require.NoError(t, err)
	require.NotNil(t, res.Stream)
	assert.Equal(t, 200, res.StatusCode, "the status went out with the head block")

	var got []string
	for line, lineErr := range res.Stream {
		require.NoError(t, lineErr)
		got = append(got, string(line))
	}
	assert.Equal(t, []string{string(lines[0]), ""}, got[:2], "only the block the head cleared is relayed")
	assert.NotContains(t, got, string(lines[2]), "the block the verdict was about is never written")
	assert.Equal(t, []string{
		`data: {"id":"c","object":"chat.completion.chunk","choices":` +
			`[{"index":0,"delta":{},"finish_reason":"content_filter"}]}`, "",
		`data: {"error":{"message":"blocked mid-stream","type":"content_filter"}}`, "",
		"data: [DONE]", "",
	}, got[2:])

	require.Eventually(t, func() bool {
		return pulled.Load() == int64(len(lines))
	}, time.Second, 5*time.Millisecond,
		"the cut must leave the rest of the upstream to the background drain, usage chunk included")
}

// TestForward_PostResponseWaitsForTheCutDrain is the ordering B8.4's acceptance
// criterion actually needs. Usage rides the last chunk, and on a cut that chunk
// is still upstream when the terminator reaches the client: a post_response that
// fired on the next statement would hand token_rate_limiter a req.Metadata the
// drain had not written yet, charging a blocked stream nothing — and it would
// read that map while the drain's goroutine was writing it, which is a fatal
// concurrent map access rather than a stale number.
//
// The client is not what waits. Its whole body is collected below before the
// drain is released, so the terminator reached it while the upstream was still
// being read.
func TestForward_PostResponseWaitsForTheCutDrain(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()

	lines := [][]byte{
		[]byte(`data: {"id":"c","choices":[{"index":0,"delta":{"content":"one"}}]}`), {},
		[]byte(`data: {"id":"c","choices":[{"index":0,"delta":{"content":"two"}}]}`), {},
		[]byte(`data: {"id":"c","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`), {},
	}
	release := make(chan struct{})
	var pulled atomic.Int64
	held := func(yield func([]byte, error) bool) {
		for i, l := range lines {
			// The usage chunk is where the drain earns its keep, so it is the
			// one the upstream withholds.
			if i == len(lines)-2 {
				<-release
			}
			pulled.Add(1)
			if !yield(l, nil) {
				return
			}
		}
	}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Stream: held}, nil).
		Once()

	seen := make(chan appplugins.ExecInput, 2)
	p := &streamInspectorPlugin{
		stubPlugin: stubPlugin{
			name:   "guardrail",
			stages: []policy.Stage{policy.StagePreResponse, policy.StagePostResponse},
			result: &appplugins.Result{StatusCode: 200},
		},
		verdict:  &appplugins.SegmentVerdict{Block: true, Type: "guardrail_violation", Message: "blocked mid-stream"},
		blockSeq: 2,
		options:  appplugins.StreamOptions{HeadChars: 1, MinCharsBetweenEvals: 1},
		postSeen: seen,
	}
	rc := streamingPolicy(t, gatewayID, p)
	fwd := forwarderWithPlugin(t, invoker, p, appproxy.WithStreamCodec(adapter.NewRegistry()))

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: []byte(`{"stream":true}`)},
	})
	require.NoError(t, err)
	require.NotNil(t, res.Stream)

	for line, lineErr := range res.Stream {
		require.NoError(t, lineErr)
		_ = line
	}

	select {
	case in := <-seen:
		t.Fatalf("post_response ran at stage %s while the drain was still reading", in.Stage)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case in := <-seen:
		assert.Equal(t, policy.StagePostResponse, in.Stage)
	case <-time.After(2 * time.Second):
		t.Fatal("post_response never ran after the drain finished")
	}
	assert.Equal(t, int64(len(lines)), pulled.Load(),
		"the drain reached the usage chunk before post_response read the request")
}
