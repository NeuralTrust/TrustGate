package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	appbackend "github.com/NeuralTrust/AgentGateway/pkg/app/backend"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
	"github.com/google/uuid"
)

var (
	// ErrStreamingNotImplemented is returned when a resolved target requests
	// streaming. The streaming data-plane is owned by B.5/B.6.
	ErrStreamingNotImplemented = errors.New("streaming path not implemented")
	// ErrNoTargetAvailable is returned when the load balancer cannot pick a
	// healthy target for the backend.
	ErrNoTargetAvailable = errors.New("no target available")
	// ErrBackendGatewayMismatch is returned when the resolved backend does not
	// belong to the gateway carried by the request.
	ErrBackendGatewayMismatch = errors.New("backend does not belong to gateway")
)

// ForwardInput carries the already-resolved routing identifiers plus the
// proxy request context built from the inbound HTTP request.
type ForwardInput struct {
	GatewayID uuid.UUID
	BackendID uuid.UUID
	Request   *infracontext.RequestContext
}

// ForwardResult is the upstream response to relay back to the client.
type ForwardResult struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

// Forwarder orchestrates the AI Gateway proxy hot path: resolve gateway and
// backend, pick a target via the load balancer, and invoke the upstream LLM
// provider on the synchronous path.
//
//go:generate mockery --name=Forwarder --dir=. --output=./mocks --filename=forwarder_mock.go --case=underscore --with-expecter
type Forwarder interface {
	Forward(ctx context.Context, in ForwardInput) (*ForwardResult, error)
}

var _ Forwarder = (*forwarder)(nil)

type forwarder struct {
	gateways appgateway.Finder
	backends appbackend.Finder
	factory  loadbalancer.Factory
	cache    cache.Client
	lbCache  *cache.TTLMap
	invoker  ProviderInvoker
	logger   *slog.Logger
}

func NewForwarder(
	gateways appgateway.Finder,
	backends appbackend.Finder,
	factory loadbalancer.Factory,
	cacheClient cache.Client,
	manager *cache.TTLMapManager,
	invoker ProviderInvoker,
	logger *slog.Logger,
) Forwarder {
	return &forwarder{
		gateways: gateways,
		backends: backends,
		factory:  factory,
		cache:    cacheClient,
		lbCache:  manager.GetTTLMap(cache.LoadBalancerTTLName),
		invoker:  invoker,
		logger:   logger,
	}
}

func (f *forwarder) Forward(ctx context.Context, in ForwardInput) (*ForwardResult, error) {
	if _, err := f.gateways.FindByID(ctx, in.GatewayID); err != nil {
		return nil, err
	}

	bk, err := f.backends.FindByID(ctx, in.BackendID)
	if err != nil {
		return nil, err
	}
	if bk.GatewayID != in.GatewayID {
		return nil, ErrBackendGatewayMismatch
	}

	lb, err := f.loadBalancerFor(bk)
	if err != nil {
		return nil, err
	}

	target, err := lb.NextTarget(in.Request)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNoTargetAvailable, err.Error())
	}

	// Streaming targets are deferred to the streaming data-plane (B.5/B.6).
	if target.Stream {
		return nil, ErrStreamingNotImplemented
	}

	// TODO(B.3): run the PreRequest plugin stage here once the plugin engine
	// is ported; bail out early on StopProcessing.

	resp, err := f.invoker.Invoke(ctx, target, in.Request)
	if err != nil {
		lb.ReportFailure(target, err)
		return nil, err
	}
	lb.ReportSuccess(target)

	// TODO(B.3): run the PreResponse/PostResponse plugin stages here.
	// TODO(metrics): emit usage extraction + telemetry traces here.

	return &ForwardResult{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
	}, nil
}

// loadBalancerFor returns a cached load balancer for the backend or builds and
// caches a new one. The instance is keyed by backend ID in the shared "lb" TTL
// map so concurrent requests reuse the same balancer state.
func (f *forwarder) loadBalancerFor(bk *domain.Backend) (*loadbalancer.LoadBalancer, error) {
	key := bk.ID.String()
	if cached, ok := f.lbCache.Get(key); ok {
		if lb, ok := cached.(*loadbalancer.LoadBalancer); ok {
			return lb, nil
		}
		f.logger.Warn("load balancer cache entry failed type assertion; rebuilding",
			slog.String("backend_id", key))
		f.lbCache.Delete(key)
	}

	lb, err := loadbalancer.NewLoadBalancer(f.factory, bk, f.logger, f.cache)
	if err != nil {
		return nil, err
	}
	f.lbCache.Set(key, lb)
	return lb, nil
}
