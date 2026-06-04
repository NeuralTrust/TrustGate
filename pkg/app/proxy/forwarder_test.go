package proxy_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/AgentGateway/pkg/app/proxy/mocks"
	appsession "github.com/NeuralTrust/AgentGateway/pkg/app/session"
	domainconsumer "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	cachemocks "github.com/NeuralTrust/AgentGateway/pkg/infra/cache/mocks"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newPermissiveCache(t *testing.T) *cachemocks.Client {
	t.Helper()
	c := cachemocks.NewClient(t)
	c.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	c.EXPECT().Get(mock.Anything, mock.Anything).Return("", errors.New("miss")).Maybe()
	c.EXPECT().RedisClient().Return(nil).Maybe()
	return c
}

func routableConsumerWith(gatewayID ids.GatewayID, registries ...*registrydomain.Registry) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{
		Consumer: &domainconsumer.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gatewayID,
			Name:      "test-consumer",
			Path:      "/v1/chat/completions",
			Algorithm: loadbalancer.AlgorithmRoundRobin,
		},
		Registries: registries,
	}
}

func backendFor(gatewayID ids.GatewayID, provider string) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: gatewayID,
		Name:      "test-backend",
		Provider:  provider,
		Weight:    1,
		Auth:      registrydomain.NewAPIKeyAuth("sk-1"),
	}
}

func newTestForwarder(t *testing.T, invoker appproxy.ProviderInvoker) appproxy.Forwarder {
	mgr := cache.NewTTLMapManager(time.Minute)
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil),
		newPermissiveCache(t), mgr, invoker, nil, nil, nil, newTestLogger(),
	)
}

type fakeSessionStore struct {
	last     string
	recorded []appsession.RecordInput
}

func (f *fakeSessionStore) Record(_ context.Context, in appsession.RecordInput) {
	f.recorded = append(f.recorded, in)
}

func (f *fakeSessionStore) LastTurnID(_ context.Context, _, _ string) string {
	return f.last
}

func newTestForwarderWithStore(t *testing.T, invoker appproxy.ProviderInvoker, store appsession.Store) appproxy.Forwarder {
	mgr := cache.NewTTLMapManager(time.Minute)
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil),
		newPermissiveCache(t), mgr, invoker, nil, store, nil, newTestLogger(),
	)
}

func enabledFallback(chain ...ids.RegistryID) *domainconsumer.Fallback {
	return &domainconsumer.Fallback{
		Enabled:  true,
		Triggers: []domainconsumer.FallbackTrigger{domainconsumer.TriggerHTTP5xx},
		Budget:   domainconsumer.FallbackBudget{MaxAttempts: 10},
		Chain:    chain,
	}
}

func TestForward_PoolFailoverOn503(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk1 := backendFor(gatewayID, "openai")
	bk2 := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, bk1, bk2)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 503, Body: []byte("down")}, nil).
		Once()
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 || string(res.Body) != "ok" {
		t.Fatalf("expected failover to 200/ok, got %d/%q", res.StatusCode, string(res.Body))
	}
}

func TestForward_FallbackChainAfterPoolExhausted(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	pool := backendFor(gatewayID, "openai")
	fallbackBk := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, pool)
	rc.Consumer.Fallback = enabledFallback(fallbackBk.ID)
	rc.FallbackBackends = []*registrydomain.Registry{fallbackBk}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 503, Body: []byte("down")}, nil).
		Once()
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("recovered")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 || string(res.Body) != "recovered" {
		t.Fatalf("expected fallback chain success 200/recovered, got %d/%q", res.StatusCode, string(res.Body))
	}
}

func TestForward_AllCandidatesFailRelaysLast5xx(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	pool := backendFor(gatewayID, "openai")
	fallbackBk := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, pool)
	rc.Consumer.Fallback = enabledFallback(fallbackBk.ID)
	rc.FallbackBackends = []*registrydomain.Registry{fallbackBk}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 502, Body: []byte("bad gateway")}, nil)

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 502 {
		t.Fatalf("expected last 5xx relayed verbatim, got %d", res.StatusCode)
	}
}

func TestForward_SyncSuccess(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 || string(res.Body) != "ok" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestForward_RecordsLLMSpanWithUsage(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{
			StatusCode: 200,
			Body:       []byte("ok"),
			Usage:      &adapter.CanonicalUsage{InputTokens: 8, OutputTokens: 2, TotalTokens: 10},
			ResponseID: "chatcmpl-xyz",
		}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)

	rt := trace.New("trace-1", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)

	_, err := fwd.Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Context: ctx},
	})
	require.NoError(t, err)

	spans := rt.Spans()
	require.Len(t, spans, 1, "one LLM span per attempt")
	assert.Equal(t, trace.SpanLLM, spans[0].Type)
	require.NotNil(t, spans[0].LLM)
	assert.Equal(t, "openai", spans[0].LLM.Provider)
	assert.Equal(t, "chatcmpl-xyz", spans[0].LLM.TurnID, "provider response id captured as turn id")
	assert.Equal(t, 200, spans[0].StatusCode())

	usage := rt.LLMUsage()
	require.NotNil(t, usage, "non-streaming usage must land on the LLM span")
	assert.Equal(t, 10, usage.TotalTokens)
}

func TestForward_RecordsSessionTurnOnSuccess(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok"), Model: "gpt-4o", ResponseID: "resp_turn"}, nil).
		Once()

	store := &fakeSessionStore{}
	fwd := newTestForwarderWithStore(t, invoker, store)

	rt := trace.New("trace-1", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)
	_, err := fwd.Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Context: ctx, GatewayID: gatewayID.String(), SessionID: "sess-1"},
	})
	require.NoError(t, err)

	require.Len(t, store.recorded, 1)
	assert.Equal(t, "resp_turn", store.recorded[0].TurnID)
	assert.Equal(t, "sess-1", store.recorded[0].SessionID)
	assert.Equal(t, gatewayID.String(), store.recorded[0].GatewayID)
	assert.Equal(t, "openai", store.recorded[0].Provider)
}

func TestForward_DoesNotRecordWithoutSession(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok"), ResponseID: "resp_turn"}, nil).
		Once()

	store := &fakeSessionStore{}
	fwd := newTestForwarderWithStore(t, invoker, store)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Context: context.Background(), GatewayID: gatewayID.String()},
	})
	require.NoError(t, err)
	assert.Empty(t, store.recorded, "no session id means nothing to record")
}

func TestForward_StampsContinuationFromStore(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	store := &fakeSessionStore{last: "resp_prev"}
	fwd := newTestForwarderWithStore(t, invoker, store)

	req := &infracontext.RequestContext{Context: context.Background(), GatewayID: gatewayID.String(), SessionID: "sess-1"}
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: req})
	require.NoError(t, err)

	assert.Equal(t, "resp_prev", req.PreviousResponseID, "last turn id is stamped for the invoker to thread")
}

func TestForward_BackendErrorStatusPassthrough(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	backendBody := []byte(`{"error":"rate limited"}`)
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{
			StatusCode: 429,
			Headers:    map[string][]string{"Retry-After": {"5"}},
			Body:       backendBody,
		}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 429 {
		t.Fatalf("status = %d, want 429", res.StatusCode)
	}
	if string(res.Body) != string(backendBody) {
		t.Fatalf("body = %q, want %q", string(res.Body), string(backendBody))
	}
	if got := res.Headers["Retry-After"]; len(got) != 1 || got[0] != "5" {
		t.Fatalf("Retry-After header = %v, want [5]", got)
	}
}

func TestForward_StreamingRequestInvokesStream(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	stream := func(yield func([]byte, error) bool) {
		yield([]byte("data: {}"), nil)
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Stream: stream}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"gpt-4","stream":true}`),
		},
	})
	if err != nil {
		t.Fatalf("Forward returned error: %v", err)
	}
	if res.Stream == nil {
		t.Fatal("expected ForwardResult.Stream to be set on the streaming branch")
	}
	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
}

func TestForward_ProviderErrorPropagates(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	errProvider := errors.New("provider boom")
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(nil, errProvider).
		Once()

	fwd := newTestForwarder(t, invoker)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if !errors.Is(err, errProvider) {
		t.Fatalf("err = %v, want errProvider", err)
	}
}

func TestForward_NoBackendsInPool(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID)

	invoker := proxymocks.NewProviderInvoker(t)
	fwd := newTestForwarder(t, invoker)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if !errors.Is(err, appproxy.ErrNoBackendsInPool) {
		t.Fatalf("err = %v, want ErrNoBackendsInPool", err)
	}
}

func TestForward_NilConsumer(t *testing.T) {
	invoker := proxymocks.NewProviderInvoker(t)
	fwd := newTestForwarder(t, invoker)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Consumer:  nil,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if !errors.Is(err, appproxy.ErrNoBackendsInPool) {
		t.Fatalf("err = %v, want ErrNoBackendsInPool", err)
	}
}
