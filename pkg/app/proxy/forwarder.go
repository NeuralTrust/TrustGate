package proxy

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
)

var (
	ErrNoBackendAvailable = errors.New("no backend available")
	ErrNoBackendsInPool   = errors.New("consumer has no backends in pool")
)

// ForwardInput carries the resolved routing identity (gateway + routable
// consumer) plus the proxy request context built from the inbound HTTP request.
// The consumer's backends form the load-balancing pool.
type ForwardInput struct {
	GatewayID uuid.UUID
	Consumer  *appconsumer.RoutableConsumer
	Request   *infracontext.RequestContext
}

// ForwardResult is the backend response to relay back to the client. Stream is
// set instead of Body for streaming targets; the handler writes the SSE
// sequence and is responsible for draining it.
type ForwardResult struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	Stream     iter.Seq2[[]byte, error]
}

type forwardRequestDTO struct {
	backend  *domain.Backend
	request  *infracontext.RequestContext
	response *infracontext.ResponseContext
	policies []*policydomain.Policy
}

//go:generate mockery --name=Forwarder --dir=. --output=./mocks --filename=forwarder_mock.go --case=underscore --with-expecter
type Forwarder interface {
	Forward(ctx context.Context, in ForwardInput) (*ForwardResult, error)
}

var _ Forwarder = (*forwarder)(nil)

type forwarder struct {
	factory    loadbalancer.Factory
	cache      cache.Client
	lbCache    *cache.TTLMap
	lbGroup    singleflight.Group
	invoker    ProviderInvoker
	executor   appplugins.Executor
	maxRetries int
	logger     *slog.Logger
}

func NewForwarder(
	factory loadbalancer.Factory,
	cacheClient cache.Client,
	manager *cache.TTLMapManager,
	invoker ProviderInvoker,
	executor appplugins.Executor,
	cfg *config.Config,
	logger *slog.Logger,
) Forwarder {
	return &forwarder{
		factory:    factory,
		cache:      cacheClient,
		lbCache:    manager.GetTTLMap(cache.LoadBalancerTTLName),
		invoker:    invoker,
		executor:   executor,
		maxRetries: maxRetriesFromConfig(cfg),
		logger:     logger,
	}
}

// maxRetriesFromConfig reads the provider retry budget, tolerating a nil config
// (used by some unit tests) and clamping negatives to zero.
func maxRetriesFromConfig(cfg *config.Config) int {
	if cfg == nil || cfg.Provider.MaxRetries < 0 {
		return 0
	}
	return cfg.Provider.MaxRetries
}

func (f *forwarder) Forward(ctx context.Context, in ForwardInput) (*ForwardResult, error) {
	if in.Consumer == nil || in.Consumer.Consumer == nil || len(in.Consumer.Backends) == 0 {
		return nil, ErrNoBackendsInPool
	}

	lb, bk, err := f.selectBackend(in.Consumer, in.Request)
	if err != nil {
		return nil, err
	}

	in.Request.BackendID = bk.ID.String()
	resp := &infracontext.ResponseContext{
		Context:   ctx,
		GatewayID: in.Request.GatewayID,
		BackendID: in.Request.BackendID,
	}
	policies := in.Consumer.Policies

	if short, err := f.runPreRequest(ctx, policies, in.Request, resp); err != nil {
		return nil, err
	} else if short != nil {
		return short, nil
	}

	dto := &forwardRequestDTO{backend: bk, request: in.Request, response: resp, policies: policies}
	stream := DetectStream(dto.request)

	providerResp, err := f.invokeWithFailover(ctx, lb, dto, stream)
	if err != nil {
		return nil, err
	}

	// A streaming request that actually opened a stream is finalized on the
	// streaming path; a pre-stream non-2xx response (Stream nil) is finalized as
	// a body so PreResponse/PostResponse still run.
	if stream && providerResp.Stream != nil {
		return f.finalizeStream(ctx, dto, providerResp), nil
	}
	return f.finalizeBody(ctx, dto, providerResp), nil
}

// invokeWithFailover invokes the selected backend and, on a retryable failure
// (transport error or a backend failure status: 5xx/429/408), reports the
// failure to the load balancer, asks it for the next backend and retries, up to
// 1+maxRetries attempts. A streaming response that already opened a stream is
// committed and never retried. When all attempts are exhausted it relays the
// last backend response verbatim (e.g. a 5xx the client should see) or returns
// the last transport error.
func (f *forwarder) invokeWithFailover(
	ctx context.Context,
	lb *loadbalancer.LoadBalancer,
	dto *forwardRequestDTO,
	stream bool,
) (*ProviderResponse, error) {
	attempts := f.maxRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	var (
		resp *ProviderResponse
		err  error
	)
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			next, selErr := lb.NextBackend(dto.request)
			if selErr != nil {
				break
			}
			f.retarget(dto, next)
		}

		resp, err = f.invokeOnce(ctx, dto.backend, dto.request, stream)
		if err == nil && !isRetryableResponse(resp, stream) {
			lb.ReportSuccess(dto.backend)
			return resp, nil
		}

		reason := failureReason(resp, err)
		lb.ReportFailure(dto.backend, reason)
		if attempt < attempts-1 {
			f.logger.Warn("backend invocation failed; retrying with next backend",
				slog.String("backend_id", dto.backend.ID.String()),
				slog.String("provider", dto.backend.Provider),
				slog.Int("attempt", attempt+1),
				slog.Int("max_attempts", attempts),
				slog.String("reason", reason.Error()),
			)
		}
	}

	// Exhausted: relay the last backend response (e.g. a 5xx) verbatim, or
	// surface the last transport error when no response was produced.
	if resp != nil {
		return resp, nil
	}
	if err == nil {
		err = ErrNoBackendAvailable
	}
	return nil, err
}

// invokeOnce performs a single backend call on the streaming or synchronous
// path. Both invoker methods share the (*ProviderResponse, error) contract.
func (f *forwarder) invokeOnce(
	ctx context.Context,
	bk *domain.Backend,
	req *infracontext.RequestContext,
	stream bool,
) (*ProviderResponse, error) {
	if stream {
		return f.invoker.InvokeStream(ctx, bk, req)
	}
	return f.invoker.Invoke(ctx, bk, req)
}

// retarget points the in-flight request at a different backend for a retry so
// downstream metadata (request/response BackendID) reflects the backend used.
func (f *forwarder) retarget(dto *forwardRequestDTO, bk *domain.Backend) {
	dto.backend = bk
	dto.request.BackendID = bk.ID.String()
	if dto.response != nil {
		dto.response.BackendID = bk.ID.String()
	}
}

// isRetryableResponse reports whether a (non-error) provider response should be
// retried. A response that already carries a stream is committed and never
// retried; otherwise a backend failure status (5xx/429/408) is retryable while
// 2xx and other 4xx are terminal.
func isRetryableResponse(resp *ProviderResponse, stream bool) bool {
	if resp == nil {
		return false
	}
	if stream && resp.Stream != nil {
		return false
	}
	return backendFailureStatus(resp.StatusCode)
}

// failureReason builds the error recorded against the backend's passive health,
// preferring the transport error and falling back to the HTTP status.
func failureReason(resp *ProviderResponse, err error) error {
	if err != nil {
		return err
	}
	if resp != nil {
		return fmt.Errorf("backend responded with status %d", resp.StatusCode)
	}
	return ErrNoBackendAvailable
}

// finalizeStream runs the response plugins and wraps the backend stream with the
// post-response hook.
func (f *forwarder) finalizeStream(
	ctx context.Context,
	dto *forwardRequestDTO,
	providerResp *ProviderResponse,
) *ForwardResult {
	pluginResp := dto.response
	mergeProviderResponse(pluginResp, providerResp, true)
	f.runPreResponse(ctx, dto.policies, dto.request, pluginResp)
	return &ForwardResult{
		StatusCode: providerResp.StatusCode,
		Headers:    pluginResp.Headers,
		Stream:     f.wrapStreamWithPostResponse(dto.policies, dto.request, pluginResp, providerResp.Stream),
	}
}

// finalizeBody runs the response plugins for a buffered backend response (the
// synchronous path or a pre-stream non-2xx response on the streaming path).
func (f *forwarder) finalizeBody(
	ctx context.Context,
	dto *forwardRequestDTO,
	providerResp *ProviderResponse,
) *ForwardResult {
	pluginResp := dto.response
	mergeProviderResponse(pluginResp, providerResp, false)
	f.runPreResponse(ctx, dto.policies, dto.request, pluginResp)
	f.firePostResponse(dto.policies, dto.request, pluginResp)
	return &ForwardResult{
		StatusCode: pluginResp.StatusCode,
		Headers:    pluginResp.Headers,
		Body:       pluginResp.Body,
	}
}

// selectBackend resolves the load balancer for the consumer's pool and asks it
// for the next backend in a single step. Wraps the LB lookup error verbatim and
// the strategy error with ErrNoBackendAvailable so callers only need a single
// error check.
func (f *forwarder) selectBackend(
	rc *appconsumer.RoutableConsumer,
	req *infracontext.RequestContext,
) (*loadbalancer.LoadBalancer, *domain.Backend, error) {
	lb, err := f.loadBalancerFor(rc)
	if err != nil {
		return nil, nil, err
	}
	bk, err := lb.NextBackend(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrNoBackendAvailable, err.Error())
	}
	return lb, bk, nil
}

// loadBalancerFor returns a cached load balancer for the consumer's pool or
// builds and caches a new one. The instance is keyed by "<gatewayID>:<consumerID>"
// in the shared "lb" TTL map so concurrent requests reuse the same balancer state
// and gateway-scoped invalidation can evict every consumer's balancer by prefix.
// singleflight collapses concurrent cache-miss builds onto a single construction.
func (f *forwarder) loadBalancerFor(rc *appconsumer.RoutableConsumer) (*loadbalancer.LoadBalancer, error) {
	key := loadBalancerCacheKey(rc.Consumer.GatewayID, rc.Consumer.ID)
	if lb, ok := f.cachedLoadBalancer(key); ok {
		return lb, nil
	}

	built, err, _ := f.lbGroup.Do(key, func() (interface{}, error) {
		if lb, ok := f.cachedLoadBalancer(key); ok {
			return lb, nil
		}
		pool := loadbalancer.Pool{
			ID:              key,
			Backends:        rc.Backends,
			Algorithm:       rc.Consumer.Algorithm,
			EmbeddingConfig: rc.Consumer.EmbeddingConfig,
		}
		lb, err := loadbalancer.NewLoadBalancer(f.factory, pool, f.logger, f.cache)
		if err != nil {
			return nil, err
		}
		f.lbCache.Set(key, lb)
		return lb, nil
	})
	if err != nil {
		return nil, err
	}
	return built.(*loadbalancer.LoadBalancer), nil
}

// cachedLoadBalancer returns the cached balancer for key, dropping and reporting
// a malformed entry so the caller rebuilds it.
func (f *forwarder) cachedLoadBalancer(key string) (*loadbalancer.LoadBalancer, bool) {
	cached, ok := f.lbCache.Get(key)
	if !ok {
		return nil, false
	}
	lb, ok := cached.(*loadbalancer.LoadBalancer)
	if !ok {
		f.logger.Warn("load balancer cache entry failed type assertion; rebuilding",
			slog.String("lb_key", key))
		f.lbCache.Delete(key)
		return nil, false
	}
	return lb, true
}

// loadBalancerCacheKey scopes the cached balancer to its gateway so a gateway
// configuration change can evict all of its consumers' balancers by prefix.
func loadBalancerCacheKey(gatewayID, consumerID uuid.UUID) string {
	return gatewayID.String() + ":" + consumerID.String()
}
