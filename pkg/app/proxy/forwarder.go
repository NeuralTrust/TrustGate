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

type ForwardInput struct {
	GatewayID uuid.UUID
	Consumer  *appconsumer.RoutableConsumer
	Request   *infracontext.RequestContext
}

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

func (f *forwarder) invokeWithFailover(
	ctx context.Context,
	lb *loadbalancer.LoadBalancer,
	rc *appconsumer.RoutableConsumer,
	dto *forwardRequestDTO,
	stream bool,
) (*ForwardResult, error) {
	fb := rc.Consumer.Fallback
	triggers := triggersFrom(fb)
	attemptsPerBackend := f.attemptsPerBackend()
	budget := newFailoverBudget(fb)
	excluded := make(map[uuid.UUID]struct{})

	last := failoverState{}
	current := dto.backend
	fromFallback := false
	for current != nil {
		f.retarget(dto, current)
		for r := 0; r < attemptsPerBackend; r++ {
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

type failoverState struct {
	resp      *ProviderResponse
	err       error
	rejection *ForwardResult
}

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

func (f *forwarder) attemptsPerBackend() int {
	if f.maxRetries < 0 {
		return 1
	}
	return f.maxRetries + 1
}

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

func (f *forwarder) logRetry(bk *domain.Backend, reason error, budget *failoverBudget) {
	f.logger.Warn("backend invocation failed; failing over",
		slog.String("backend_id", bk.ID.String()),
		slog.String("provider", bk.Provider),
		slog.Int("attempt", budget.attempts),
		slog.String("reason", reason.Error()),
	)
}

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

func (f *forwarder) retarget(dto *forwardRequestDTO, bk *domain.Backend) {
	dto.backend = bk
	dto.request.BackendID = bk.ID.String()
	if dto.response != nil {
		dto.response.BackendID = bk.ID.String()
	}
}

func failureReason(resp *ProviderResponse, err error) error {
	if err != nil {
		return err
	}
	if resp != nil {
		return fmt.Errorf("backend responded with status %d", resp.StatusCode)
	}
	return ErrNoBackendAvailable
}

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

func loadBalancerCacheKey(gatewayID, consumerID uuid.UUID) string {
	return gatewayID.String() + ":" + consumerID.String()
}
