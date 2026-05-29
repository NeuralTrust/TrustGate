package backend

import (
	"context"
	"log/slog"
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
	"github.com/google/uuid"
)

//go:generate mockery --name=BackendResolver --dir=. --output=./mocks --filename=backend_resolver_mock.go --case=underscore --with-expecter
type BackendResolver interface {
	// GetOrCreateLoadBalancer returns the ready-to-use load balancer for a
	// backend, building and caching it on first use. Steady-state calls resolve
	// in O(1) from memory with no database query and no balancer rebuild.
	GetOrCreateLoadBalancer(ctx context.Context, backendID uuid.UUID) (*loadbalancer.LoadBalancer, error)
}

var _ BackendResolver = (*backendResolver)(nil)

type backendResolver struct {
	finder      Finder
	factory     loadbalancer.Factory
	cache       cache.Client
	memoryCache *cache.TTLMap
	buildMu     sync.Mutex
	logger      *slog.Logger
}

func NewBackendResolver(
	finder Finder,
	factory loadbalancer.Factory,
	cacheClient cache.Client,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
) BackendResolver {
	return &backendResolver{
		finder:      finder,
		factory:     factory,
		cache:       cacheClient,
		memoryCache: manager.GetTTLMap(cache.LoadBalancerTTLName),
		logger:      logger,
	}
}

func (r *backendResolver) GetOrCreateLoadBalancer(
	ctx context.Context,
	backendID uuid.UUID,
) (*loadbalancer.LoadBalancer, error) {
	key := backendID.String()
	if lb, ok := r.cachedLoadBalancer(key); ok {
		return lb, nil
	}

	// Single-flight build: serialize concurrent misses so we never spawn (and
	// then leak) more than one balancer goroutine per backend. The double-check
	// returns the instance a racing caller may have just cached.
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	if lb, ok := r.cachedLoadBalancer(key); ok {
		return lb, nil
	}

	bk, err := r.finder.FindByID(ctx, backendID)
	if err != nil {
		return nil, err
	}

	lb, err := loadbalancer.NewLoadBalancer(r.factory, bk, r.logger, r.cache)
	if err != nil {
		return nil, err
	}

	r.memoryCache.Set(key, lb)
	return lb, nil
}

func (r *backendResolver) cachedLoadBalancer(key string) (*loadbalancer.LoadBalancer, bool) {
	cached, ok := r.memoryCache.Get(key)
	if !ok {
		return nil, false
	}
	lb, ok := cached.(*loadbalancer.LoadBalancer)
	if !ok {
		r.logger.Warn("load balancer cache entry failed type assertion; rebuilding",
			slog.String("backend_id", key))
		r.memoryCache.Delete(key)
		return nil, false
	}
	return lb, true
}
