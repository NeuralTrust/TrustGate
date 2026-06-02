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
	domainbackend "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	domainconsumer "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	cachemocks "github.com/NeuralTrust/AgentGateway/pkg/infra/cache/mocks"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
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

func routableConsumerWith(gatewayID uuid.UUID, backends ...*domainbackend.Backend) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{
		Consumer: &domainconsumer.Consumer{
			ID:        uuid.New(),
			GatewayID: gatewayID,
			Name:      "test-consumer",
			Path:      "/v1/chat/completions",
			Algorithm: loadbalancer.AlgorithmRoundRobin,
		},
		Backends: backends,
	}
}

func backendFor(gatewayID uuid.UUID, provider string) *domainbackend.Backend {
	return &domainbackend.Backend{
		ID:        uuid.New(),
		GatewayID: gatewayID,
		Name:      "test-backend",
		Provider:  provider,
		Weight:    1,
		Auth:      domainbackend.NewAPIKeyAuth("sk-1"),
	}
}

func newTestForwarder(t *testing.T, invoker appproxy.ProviderInvoker) appproxy.Forwarder {
	mgr := cache.NewTTLMapManager(time.Minute)
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil),
		newPermissiveCache(t), mgr, invoker, nil, nil, newTestLogger(),
	)
}

func enabledFallback(chain ...uuid.UUID) *domainconsumer.Fallback {
	return &domainconsumer.Fallback{
		Enabled:  true,
		Triggers: []domainconsumer.FallbackTrigger{domainconsumer.TriggerHTTP5xx},
		Budget:   domainconsumer.FallbackBudget{MaxAttempts: 10},
		Chain:    chain,
	}
}

func TestForward_PoolFailoverOn503(t *testing.T) {
	gatewayID := uuid.New()
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
	gatewayID := uuid.New()
	pool := backendFor(gatewayID, "openai")
	fallbackBk := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, pool)
	rc.Consumer.Fallback = enabledFallback(fallbackBk.ID)
	rc.FallbackBackends = []*domainbackend.Backend{fallbackBk}

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
	gatewayID := uuid.New()
	pool := backendFor(gatewayID, "openai")
	fallbackBk := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, pool)
	rc.Consumer.Fallback = enabledFallback(fallbackBk.ID)
	rc.FallbackBackends = []*domainbackend.Backend{fallbackBk}

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
	gatewayID := uuid.New()
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

func TestForward_BackendErrorStatusPassthrough(t *testing.T) {
	gatewayID := uuid.New()
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
	gatewayID := uuid.New()
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

	// Streaming is auto-detected from the request body ("stream": true).
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
	gatewayID := uuid.New()
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
	gatewayID := uuid.New()
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
		GatewayID: uuid.New(),
		Consumer:  nil,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if !errors.Is(err, appproxy.ErrNoBackendsInPool) {
		t.Fatalf("err = %v, want ErrNoBackendsInPool", err)
	}
}
