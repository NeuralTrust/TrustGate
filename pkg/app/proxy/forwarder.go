package proxy

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/metric_events"
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

	return f.invokeWithFailover(ctx, lb, in.Consumer, dto, stream)
}

// invokeWithFailover runs the request through the consumer's failover policy.
// It walks two tiers of candidate backends, giving each backend up to
// retriesPerBackend attempts before moving on:
//
//   - Tier 1 (pool): backends picked by the load balancer, excluding ones
//     already tried this request (so e.g. round-robin over a single backend does
//     not loop forever).
//   - Tier 2 (fallback chain): the consumer's Fallback.Chain in strict priority
//     order, walked only after the pool is exhausted.
//
// Each attempt is classified (success / retryable / terminal). A committed
// stream or accepted buffered success is finalized and returned immediately; a
// terminal 4xx is relayed verbatim without failover; a retryable outcome reports
// failure to the LB and advances. When the plugin_rejection trigger is enabled,
// a buffered success rejected by a PreResponse plugin also fails over to the
// next candidate. An enabled fallback's Budget (MaxAttempts, MaxTotalLatency) is
// the global ceiling. When everything is exhausted the last result is relayed
// (a backend 5xx, the last plugin rejection, or the last transport error).
func (f *forwarder) invokeWithFailover(
	ctx context.Context,
	lb *loadbalancer.LoadBalancer,
	rc *appconsumer.RoutableConsumer,
	dto *forwardRequestDTO,
	stream bool,
) (*ForwardResult, error) {
	fb := rc.Consumer.Fallback
	triggers := triggersFrom(fb)
	retriesPerBackend := f.retriesPerBackend()
	budget := newFailoverBudget(fb)
	excluded := make(map[uuid.UUID]struct{})

	last := failoverState{}
	current := dto.backend
	fromFallback := false
	for current != nil {
		f.retarget(dto, current)
		for r := 0; r < retriesPerBackend; r++ {
			if budget.exhausted() {
				return f.relayLast(ctx, dto, last)
			}
			budget.recordAttempt()

			startedAt := time.Now()
			resp, err := f.invokeOnce(ctx, current, dto.request, stream)
			elapsed := time.Since(startedAt)
			outcome := classifyOutcome(resp, err, triggers)
			f.emitHop(ctx, current, fromFallback, budget.attempts, outcome, resp, elapsed)
			switch outcome {
			case OutcomeSuccess:
				lb.ReportSuccess(current)
				if stream && resp.Stream != nil {
					return f.finalizeStream(ctx, dto, resp), nil
				}
				result, pe := f.finalizeBodyGated(ctx, dto, resp)
				if pe == nil || !triggers.pluginRejection {
					return result, nil
				}
				// The backend answered fine but a response plugin rejected the
				// payload and the trigger is enabled: skip the remaining
				// same-backend retries (a deterministic rejection would only
				// repeat) and fail over to the next candidate, remembering the
				// rejection to relay if nothing better is produced.
				last = failoverState{rejection: result}
				f.logRetry(current, pe, budget)
			case OutcomeTerminal:
				lb.ReportSuccess(current)
				return f.finalizeBody(ctx, dto, resp), nil
			case OutcomeRetryable:
				reason := failureReason(resp, err)
				lb.ReportFailure(current, reason)
				last = failoverState{resp: resp, err: err}
				f.logRetry(current, reason, budget)
				continue
			}
			break
		}
		excluded[current.ID] = struct{}{}
		current, fromFallback = f.nextCandidate(lb, rc, dto.request, excluded)
	}

	return f.relayLast(ctx, dto, last)
}

// failoverState tracks the most recent attempt outcome so the loop can relay a
// sensible result once every candidate is exhausted: the last plugin rejection
// (when nothing better was produced), else the last backend response finalized
// verbatim, else the last transport error.
type failoverState struct {
	resp      *ProviderResponse
	err       error
	rejection *ForwardResult
}

// relayLast finalizes the terminal state when the failover loop is exhausted.
func (f *forwarder) relayLast(
	ctx context.Context,
	dto *forwardRequestDTO,
	last failoverState,
) (*ForwardResult, error) {
	if last.resp != nil {
		return f.finalizeBody(ctx, dto, last.resp), nil
	}
	if last.rejection != nil {
		return last.rejection, nil
	}
	if last.err != nil {
		return nil, last.err
	}
	return nil, ErrNoBackendAvailable
}

// retriesPerBackend is the per-backend attempt budget, derived from the provider
// retry config and clamped to at least one attempt.
func (f *forwarder) retriesPerBackend() int {
	if f.maxRetries < 1 {
		return 1
	}
	return f.maxRetries
}

// nextCandidate advances to the next backend to try: first the next pool backend
// from the load balancer (excluding ones already attempted), then the fallback
// chain in priority order. The bool reports whether the returned backend comes
// from the fallback chain (vs the primary pool). Returns (nil, false) when no
// further candidate remains.
func (f *forwarder) nextCandidate(
	lb *loadbalancer.LoadBalancer,
	rc *appconsumer.RoutableConsumer,
	req *infracontext.RequestContext,
	excluded map[uuid.UUID]struct{},
) (*domain.Backend, bool) {
	if bk, err := lb.NextBackend(req, excluded); err == nil && bk != nil {
		if _, seen := excluded[bk.ID]; !seen {
			return bk, false
		}
	}
	if fb := rc.Consumer.Fallback; fb != nil && fb.Enabled {
		for _, bk := range rc.FallbackBackends {
			if _, seen := excluded[bk.ID]; !seen {
				return bk, true
			}
		}
	}
	return nil, false
}

// emitHop records a per-attempt trace event so each backend tried in a request
// is observable. The collector stamps the shared request TraceID, correlating
// every hop with the original request. elapsed is the wall-clock time spent on
// this backend call, surfaced as the hop latency.
func (f *forwarder) emitHop(
	ctx context.Context,
	bk *domain.Backend,
	fromFallback bool,
	attempt int,
	outcome Outcome,
	resp *ProviderResponse,
	elapsed time.Duration,
) {
	collector := metrics.CollectorFromContext(ctx)
	if collector == nil {
		return
	}
	latencyMs := elapsed.Milliseconds()
	evt := metric_events.NewTraceEvent()
	evt.Attempt = attempt
	evt.Fallback = fromFallback
	evt.BackendID = bk.ID.String()
	evt.Outcome = outcome.String()
	evt.EndTimestamp = time.Now().Unix()
	evt.Latency = latencyMs
	if resp != nil {
		evt.StatusCode = resp.StatusCode
	}
	if evt.Upstream != nil {
		evt.Upstream.Target.Provider = bk.Provider
		evt.Upstream.Target.Latency = latencyMs
	}
	collector.Emit(evt)
}

// logRetry emits a structured warning when a backend attempt fails and another
// candidate/retry remains.
func (f *forwarder) logRetry(bk *domain.Backend, reason error, budget *failoverBudget) {
	f.logger.Warn("backend invocation failed; failing over",
		slog.String("backend_id", bk.ID.String()),
		slog.String("provider", bk.Provider),
		slog.Int("attempt", budget.attempts),
		slog.String("reason", reason.Error()),
	)
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
// Response headers are reset before the merge so a re-finalization after
// failover (e.g. relaying the last 5xx, or a terminal response that follows an
// earlier plugin-rejected attempt) does not accumulate stale headers.
func (f *forwarder) finalizeBody(
	ctx context.Context,
	dto *forwardRequestDTO,
	providerResp *ProviderResponse,
) *ForwardResult {
	pluginResp := dto.response
	pluginResp.Headers = nil
	mergeProviderResponse(pluginResp, providerResp, false)
	f.runPreResponse(ctx, dto.policies, dto.request, pluginResp)
	f.firePostResponse(dto.policies, dto.request, pluginResp)
	return &ForwardResult{
		StatusCode: pluginResp.StatusCode,
		Headers:    pluginResp.Headers,
		Body:       pluginResp.Body,
	}
}

// finalizeBodyGated finalizes a buffered backend response while surfacing a
// PreResponse plugin rejection so the caller can decide whether to fail over.
// When a plugin rejects the payload it returns the synthetic rejection result
// and the *PluginError (PostResponse is not fired); otherwise it behaves like
// finalizeBody and returns a nil error. Response headers are reset before the
// merge so a re-finalization after failover does not accumulate stale headers.
func (f *forwarder) finalizeBodyGated(
	ctx context.Context,
	dto *forwardRequestDTO,
	providerResp *ProviderResponse,
) (*ForwardResult, *appplugins.PluginError) {
	pluginResp := dto.response
	pluginResp.Headers = nil
	mergeProviderResponse(pluginResp, providerResp, false)
	if pe := f.runPreResponseGated(ctx, dto.policies, dto.request, pluginResp); pe != nil {
		return pluginErrorResult(pe), pe
	}
	f.firePostResponse(dto.policies, dto.request, pluginResp)
	return &ForwardResult{
		StatusCode: pluginResp.StatusCode,
		Headers:    pluginResp.Headers,
		Body:       pluginResp.Body,
	}, nil
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
	bk, err := lb.NextBackend(req, nil)
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
