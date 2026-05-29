package proxy_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	appbackendmocks "github.com/NeuralTrust/AgentGateway/pkg/app/backend/mocks"
	appgatewaymocks "github.com/NeuralTrust/AgentGateway/pkg/app/gateway/mocks"
	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/AgentGateway/pkg/app/proxy/mocks"
	domainbackend "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	domaingateway "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
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

func backendWith(gatewayID uuid.UUID, target domainbackend.Target) *domainbackend.Backend {
	return &domainbackend.Backend{
		ID:        uuid.New(),
		GatewayID: gatewayID,
		Name:      "test-backend",
		Algorithm: domainbackend.AlgorithmRoundRobin,
		Targets:   domainbackend.Targets{target},
	}
}

func TestForward_SyncSuccess(t *testing.T) {
	gatewayID := uuid.New()
	bk := backendWith(gatewayID, domainbackend.Target{ID: "t1", Provider: "openai"})

	gateways := appgatewaymocks.NewFinder(t)
	gateways.EXPECT().FindByID(mock.Anything, gatewayID).Return(&domaingateway.Gateway{ID: gatewayID}, nil).Once()

	backends := appbackendmocks.NewFinder(t)
	backends.EXPECT().FindByID(mock.Anything, bk.ID).Return(bk, nil).Once()

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	mgr := cache.NewTTLMapManager(time.Minute)
	fwd := appproxy.NewForwarder(
		gateways, backends, loadbalancer.NewBaseFactory(nil, nil),
		newPermissiveCache(t), mgr, invoker, newTestLogger(),
	)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		BackendID: bk.ID,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 || string(res.Body) != "ok" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestForward_StreamingTargetNotImplemented(t *testing.T) {
	gatewayID := uuid.New()
	bk := backendWith(gatewayID, domainbackend.Target{ID: "t1", Provider: "openai", Stream: true})

	gateways := appgatewaymocks.NewFinder(t)
	gateways.EXPECT().FindByID(mock.Anything, gatewayID).Return(&domaingateway.Gateway{ID: gatewayID}, nil).Once()

	backends := appbackendmocks.NewFinder(t)
	backends.EXPECT().FindByID(mock.Anything, bk.ID).Return(bk, nil).Once()

	// Invoker must never be called on the streaming branch.
	invoker := proxymocks.NewProviderInvoker(t)

	mgr := cache.NewTTLMapManager(time.Minute)
	fwd := appproxy.NewForwarder(
		gateways, backends, loadbalancer.NewBaseFactory(nil, nil),
		newPermissiveCache(t), mgr, invoker, newTestLogger(),
	)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		BackendID: bk.ID,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if !errors.Is(err, appproxy.ErrStreamingNotImplemented) {
		t.Fatalf("err = %v, want ErrStreamingNotImplemented", err)
	}
}

func TestForward_ProviderErrorPropagates(t *testing.T) {
	gatewayID := uuid.New()
	bk := backendWith(gatewayID, domainbackend.Target{ID: "t1", Provider: "openai"})

	gateways := appgatewaymocks.NewFinder(t)
	gateways.EXPECT().FindByID(mock.Anything, gatewayID).Return(&domaingateway.Gateway{ID: gatewayID}, nil).Once()

	backends := appbackendmocks.NewFinder(t)
	backends.EXPECT().FindByID(mock.Anything, bk.ID).Return(bk, nil).Once()

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(nil, appproxy.ErrProviderNotImplemented).
		Once()

	mgr := cache.NewTTLMapManager(time.Minute)
	fwd := appproxy.NewForwarder(
		gateways, backends, loadbalancer.NewBaseFactory(nil, nil),
		newPermissiveCache(t), mgr, invoker, newTestLogger(),
	)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		BackendID: bk.ID,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if !errors.Is(err, appproxy.ErrProviderNotImplemented) {
		t.Fatalf("err = %v, want ErrProviderNotImplemented", err)
	}
}

func TestForward_BackendGatewayMismatch(t *testing.T) {
	gatewayID := uuid.New()
	bk := backendWith(uuid.New(), domainbackend.Target{ID: "t1", Provider: "openai"})

	gateways := appgatewaymocks.NewFinder(t)
	gateways.EXPECT().FindByID(mock.Anything, gatewayID).Return(&domaingateway.Gateway{ID: gatewayID}, nil).Once()

	backends := appbackendmocks.NewFinder(t)
	backends.EXPECT().FindByID(mock.Anything, bk.ID).Return(bk, nil).Once()

	invoker := proxymocks.NewProviderInvoker(t)

	mgr := cache.NewTTLMapManager(time.Minute)
	fwd := appproxy.NewForwarder(
		gateways, backends, loadbalancer.NewBaseFactory(nil, nil),
		newPermissiveCache(t), mgr, invoker, newTestLogger(),
	)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		BackendID: bk.ID,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if !errors.Is(err, appproxy.ErrBackendGatewayMismatch) {
		t.Fatalf("err = %v, want ErrBackendGatewayMismatch", err)
	}
}

func TestForward_GatewayNotFoundPropagates(t *testing.T) {
	gatewayID := uuid.New()
	wantErr := errors.New("gateway gone")

	gateways := appgatewaymocks.NewFinder(t)
	gateways.EXPECT().FindByID(mock.Anything, gatewayID).Return(nil, wantErr).Once()

	backends := appbackendmocks.NewFinder(t)
	invoker := proxymocks.NewProviderInvoker(t)

	mgr := cache.NewTTLMapManager(time.Minute)
	fwd := appproxy.NewForwarder(
		gateways, backends, loadbalancer.NewBaseFactory(nil, nil),
		newPermissiveCache(t), mgr, invoker, newTestLogger(),
	)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		BackendID: uuid.New(),
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}
