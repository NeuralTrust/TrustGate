package proxy_test

import (
	"context"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/AgentGateway/pkg/app/proxy/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
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
}

func (s *stubPlugin) Name() string                        { return s.name }
func (s *stubPlugin) MandatoryStages() []policy.Stage     { return s.stages }
func (s *stubPlugin) SupportedStages() []policy.Stage     { return s.stages }
func (s *stubPlugin) SupportedModes() []policy.Mode       { return []policy.Mode{policy.ModeEnforce} }
func (s *stubPlugin) ValidateConfig(map[string]any) error { return nil }
func (s *stubPlugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if s.ran != nil {
		s.ran <- in.Stage
	}
	return s.result, s.err
}

func forwarderWithPlugin(t *testing.T, invoker appproxy.ProviderInvoker, p appplugins.Plugin) appproxy.Forwarder {
	t.Helper()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(p))
	exec := appplugins.NewExecutor(reg, newTestLogger())
	mgr := cache.NewTTLMapManager(time.Minute)
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil),
		newPermissiveCache(t), mgr, invoker, exec, nil, nil, newTestLogger(),
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
		Request:   &infracontext.RequestContext{Context: context.Background()},
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
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	require.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "cached", string(res.Body))
	assert.Equal(t, []string{"HIT"}, res.Headers["X-Cache-Status"])
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

	req := &infracontext.RequestContext{Context: context.Background(), Body: []byte(`{"stream":true}`)}
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
		Request:   &infracontext.RequestContext{Context: context.Background()},
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
	name   string
	stages []policy.Stage
	seen   chan appplugins.ExecInput
}

func (c *capturePlugin) Name() string                        { return c.name }
func (c *capturePlugin) MandatoryStages() []policy.Stage     { return c.stages }
func (c *capturePlugin) SupportedStages() []policy.Stage     { return c.stages }
func (c *capturePlugin) SupportedModes() []policy.Mode       { return []policy.Mode{policy.ModeEnforce} }
func (c *capturePlugin) ValidateConfig(map[string]any) error { return nil }
func (c *capturePlugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if in.Stage == policy.StagePostResponse && c.seen != nil {
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

	seen := make(chan appplugins.ExecInput, 1)
	p := &capturePlugin{
		name:   "token_rate_limiter",
		stages: []policy.Stage{policy.StagePreRequest, policy.StagePostResponse},
		seen:   seen,
	}
	fwd := forwarderWithPlugin(t, invoker, p)

	req := &infracontext.RequestContext{Context: context.Background(), Body: []byte(`{"stream":true}`)}
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
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

	req := &infracontext.RequestContext{Context: context.Background(), Body: []byte(`{"stream":true}`)}
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
