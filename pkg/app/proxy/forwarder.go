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

package proxy

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	appsession "github.com/NeuralTrust/TrustGate/pkg/app/session"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"golang.org/x/sync/singleflight"
)

var (
	ErrNoBackendAvailable = errors.New("no backend available")
	ErrNoBackendsInPool   = errors.New("consumer has no registries in pool")
)

type ForwardInput struct {
	GatewayID ids.GatewayID
	Consumer  *appconsumer.RoutableConsumer
	Data      *appconsumer.Data
	RoleIDs   []ids.RoleID
	Request   *infracontext.RequestContext
}

type ForwardResult struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	Stream     iter.Seq2[[]byte, error]
}

type forwardRequestDTO struct {
	backend     *domain.Registry
	candidates  *routingdomain.CandidateSet
	routeSource string
	pinned      bool
	request     *infracontext.RequestContext
	response    *infracontext.ResponseContext
	policies    []*policydomain.Policy
	plan        *appplugins.StagePlan
	baseHeaders map[string][]string
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
	sessions   appsession.Store
	resolver   approuting.Resolver
	maxRetries int
	logger     *slog.Logger
}

func NewForwarder(
	factory loadbalancer.Factory,
	cacheClient cache.Client,
	manager *cache.TTLMapManager,
	invoker ProviderInvoker,
	executor appplugins.Executor,
	sessions appsession.Store,
	resolver approuting.Resolver,
	cfg *config.Config,
	logger *slog.Logger,
) Forwarder {
	return &forwarder{
		factory:    factory,
		cache:      cacheClient,
		lbCache:    manager.GetTTLMap(cache.LoadBalancerTTLName),
		invoker:    invoker,
		executor:   executor,
		sessions:   sessions,
		resolver:   resolver,
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
	if in.Consumer == nil || in.Consumer.Consumer == nil {
		return nil, ErrNoBackendsInPool
	}

	intent, candidates, err := f.resolveRouting(in)
	if err != nil {
		return nil, err
	}
	applyIntentToBody(in.Request, intent)

	f.stampConsumerScope(in)
	f.stampContinuation(ctx, in.Request)

	route, err := f.routeBackend(in.Consumer, in.Request, intent, candidates)
	if err != nil {
		return nil, err
	}

	stampTarget(in.Request, route.backend)
	resp := &infracontext.ResponseContext{
		Context:    ctx,
		GatewayID:  in.Request.GatewayID,
		RegistryID: in.Request.RegistryID,
	}
	policies := in.Consumer.Policies
	plan := in.Consumer.PolicyPlan

	if short, err := f.runPreRequest(ctx, policies, plan, in.Request, resp); err != nil {
		return nil, err
	} else if short != nil {
		return short, nil
	}

	dto := &forwardRequestDTO{
		backend:     route.backend,
		candidates:  candidates,
		pinned:      route.pinned,
		request:     in.Request,
		response:    resp,
		policies:    policies,
		plan:        plan,
		baseHeaders: cloneHeaders(resp.Headers),
	}
	stream := DetectStream(dto.request)

	return f.invokeWithFailover(ctx, in.Consumer, dto, stream, route)
}

func (f *forwarder) invokeWithFailover(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	dto *forwardRequestDTO,
	stream bool,
	route routedBackend,
) (*ForwardResult, error) {
	fb := rc.Consumer.Fallback
	triggers := triggersFrom(fb)
	attemptsPerBackend := f.attemptsPerBackend()
	budget := newFailoverBudget(fb)
	lb := route.lb
	excluded := route.excluded
	if excluded == nil {
		excluded = make(map[ids.RegistryID]struct{})
	}

	last := failoverState{}
	lastKind := failureNone
	current := dto.backend
	fromFallback := route.fromFallback
	for current != nil {
		f.retarget(dto, current)
		f.stampRoutingPolicy(dto, rc, current)
		for r := 0; r < attemptsPerBackend; r++ {
			if budget.exhausted() {
				return f.relayLast(ctx, dto, last)
			}
			budget.recordAttempt()

			startedAt := time.Now()
			resp, err := f.invokeOnce(ctx, current, dto.request, stream)
			elapsed := time.Since(startedAt)
			outcome := classifyOutcome(resp, err, triggers)
			span := f.recordSpan(ctx, dto, current, fromFallback, budget.attempts, outcome, resp, elapsed)
			switch outcome {
			case OutcomeSuccess:
				reportSuccess(lb, current)
				if stream && resp.Stream != nil {
					// The provider stream is lazy: invokeOnce only measured
					// time-to-first-byte. Keep the LLM span open and re-time it
					// once the stream is fully consumed so provider_ms reflects
					// the real token-generation duration instead of leaking into
					// gateway_ms.
					return f.finalizeStream(ctx, dto, resp, span, startedAt), nil
				}
				result, pe := f.finalizeBodyGated(ctx, dto, resp)
				if pe == nil || !triggers.pluginRejection {
					return result, nil
				}

				last = failoverState{rejection: result}
				lastKind = failurePluginRejection
				f.logRetry(current, pe, budget)
			case OutcomeTerminal:
				if resp == nil {
					return nil, err
				}
				reportSuccess(lb, current)
				return f.finalizeBody(ctx, dto, resp), nil
			case OutcomeRetryable:
				reason := failureReason(resp, err)
				reportFailure(lb, current, reason)
				last = failoverState{resp: resp, err: err}
				lastKind = classifyFailure(resp, err)
				f.logRetry(current, reason, budget)
				continue
			}
			break
		}
		excluded[current.ID] = struct{}{}
		if route.pinned {
			break
		}
		current, fromFallback = f.nextCandidate(lb, rc, dto.request, excluded, triggers.allowsFallback(lastKind))
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
	excluded map[ids.RegistryID]struct{},
	allowChain bool,
) (*domain.Registry, bool) {
	if isRoleBased(rc) {
		return nil, false
	}
	if lb != nil {
		if bk, err := lb.NextBackend(req, excluded); err == nil && bk != nil {
			if _, seen := excluded[bk.ID]; !seen {
				return bk, false
			}
		}
	}
	if !allowChain {
		return nil, false
	}
	if bk := firstAvailableFallback(rc, excluded); bk != nil {
		return bk, true
	}
	return nil, false
}

func reportSuccess(lb *loadbalancer.LoadBalancer, bk *domain.Registry) {
	if lb != nil {
		lb.ReportSuccess(bk)
	}
}

func reportFailure(lb *loadbalancer.LoadBalancer, bk *domain.Registry, reason error) {
	if lb != nil {
		lb.ReportFailure(bk, reason)
	}
}

func (f *forwarder) recordSpan(
	ctx context.Context,
	dto *forwardRequestDTO,
	bk *domain.Registry,
	fromFallback bool,
	attempt int,
	outcome Outcome,
	resp *ProviderResponse,
	elapsed time.Duration,
) *trace.Span {
	rt := trace.FromContext(ctx)
	if rt == nil {
		return nil
	}
	span := &trace.Span{
		Type:      trace.SpanLLM,
		Name:      bk.Provider(),
		StartedAt: time.Now().Add(-elapsed),
		LLM: &trace.LLMAttrs{
			RegistryID:     bk.ID.String(),
			Provider:       bk.Provider(),
			RequestedModel: dto.request.RequestedModel,
			Attempt:        attempt,
			Fallback:       fromFallback,
			Pinned:         dto.pinned,
			Route:          dto.routeSource,
			Outcome:        outcome.String(),
		},
	}
	if resp != nil {
		span.SetStatusCode(resp.StatusCode)
		span.ObserveUsage(resp.Usage)
		span.LLM.Model = resp.Model
		span.LLM.SentModel = resp.SentModel
		span.LLM.FinishReason = resp.FinishReason
		span.LLM.TurnID = resp.ResponseID
	}
	_ = rt.AddSpan(span)
	span.End()
	return span
}

// stampConsumerScope records the resolved consumer (and gateway) identity on the
// request so plugins can partition runtime state (e.g. rate-limit counters) by
// the policy scope without re-resolving the consumer from headers or path.
func (f *forwarder) stampConsumerScope(in ForwardInput) {
	if in.Request == nil {
		return
	}
	in.Request.ConsumerID = in.Consumer.Consumer.ID.String()
	if in.Request.GatewayID == "" {
		in.Request.GatewayID = in.Consumer.Consumer.GatewayID.String()
	}
}

func (f *forwarder) stampContinuation(ctx context.Context, req *infracontext.RequestContext) {
	if f.sessions == nil || req == nil || req.SessionID == "" {
		return
	}
	req.PreviousResponseID = f.sessions.LastTurnID(ctx, req.GatewayID, req.SessionID)
}

func (f *forwarder) recordSession(
	ctx context.Context,
	req *infracontext.RequestContext,
	turnID, provider, model string,
	statusCode int,
) {
	if f.sessions == nil || req == nil || req.SessionID == "" || turnID == "" {
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		return
	}
	f.sessions.Record(ctx, appsession.RecordInput{
		GatewayID: req.GatewayID,
		SessionID: req.SessionID,
		TurnID:    turnID,
		Provider:  provider,
		Model:     model,
	})
}

func (f *forwarder) recordSessionOnStreamEnd(
	ctx context.Context,
	req *infracontext.RequestContext,
	span *trace.Span,
	statusCode int,
	stream iter.Seq2[[]byte, error],
) iter.Seq2[[]byte, error] {
	if f.sessions == nil || span == nil || stream == nil || req == nil || req.SessionID == "" {
		return stream
	}
	return func(yield func([]byte, error) bool) {
		defer func() {
			if attrs, ok := span.LLMAttrsCopy(); ok {
				f.recordSession(ctx, req, attrs.TurnID, attrs.Provider, attrs.Model, statusCode)
			}
		}()
		for line, err := range stream {
			if !yield(line, err) {
				return
			}
		}
	}
}

func (f *forwarder) logRetry(bk *domain.Registry, reason error, budget *failoverBudget) {
	f.logger.Warn("backend invocation failed; failing over",
		slog.String("registry_id", bk.ID.String()),
		slog.String("provider", bk.Provider()),
		slog.Int("attempt", budget.attempts),
		slog.String("reason", reason.Error()),
	)
}

func (f *forwarder) invokeOnce(
	ctx context.Context,
	bk *domain.Registry,
	req *infracontext.RequestContext,
	stream bool,
) (*ProviderResponse, error) {
	if stream {
		return f.invoker.InvokeStream(ctx, bk, req)
	}
	return f.invoker.Invoke(ctx, bk, req)
}

func (f *forwarder) retarget(dto *forwardRequestDTO, bk *domain.Registry) {
	dto.backend = bk
	stampTarget(dto.request, bk)
	if dto.response != nil {
		dto.response.RegistryID = bk.ID.String()
	}
}

func stampTarget(req *infracontext.RequestContext, bk *domain.Registry) {
	req.RegistryID = bk.ID.String()
	req.Provider = bk.Provider()
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
	span *trace.Span,
	startedAt time.Time,
) *ForwardResult {
	pluginResp := dto.response
	mergeProviderResponse(pluginResp, providerResp, true)
	if pe := f.runPreResponseGated(ctx, dto.policies, dto.plan, dto.request, pluginResp); pe != nil {
		go drainStream(providerResp.Stream)
		return pluginErrorResult(pe)
	}
	out := f.wrapStreamWithPostResponse(dto.policies, dto.plan, dto.request, pluginResp, providerResp.Stream)
	out = retimeSpanOnStreamEnd(out, span, startedAt)
	out = f.recordSessionOnStreamEnd(ctx, dto.request, span, providerResp.StatusCode, out)
	return &ForwardResult{
		StatusCode: providerResp.StatusCode,
		Headers:    pluginResp.Headers,
		Stream:     out,
	}
}

// retimeSpanOnStreamEnd re-times the provider LLM span so its latency spans the
// full stream lifetime (token generation), not just the time-to-first-byte that
// invokeOnce measured. The latency is overwritten when the consumer finishes
// draining the stream, which happens before the metrics finalizer reads it.
func retimeSpanOnStreamEnd(
	stream iter.Seq2[[]byte, error],
	span *trace.Span,
	startedAt time.Time,
) iter.Seq2[[]byte, error] {
	if span == nil || stream == nil {
		return stream
	}
	return func(yield func([]byte, error) bool) {
		defer func() { span.SetLatency(time.Since(startedAt)) }()
		for line, err := range stream {
			if !yield(line, err) {
				return
			}
		}
	}
}

func (f *forwarder) finalizeBody(
	ctx context.Context,
	dto *forwardRequestDTO,
	providerResp *ProviderResponse,
) *ForwardResult {
	pluginResp := dto.response
	pluginResp.Headers = cloneHeaders(dto.baseHeaders)
	mergeProviderResponse(pluginResp, providerResp, false)
	if pe := f.runPreResponseGated(ctx, dto.policies, dto.plan, dto.request, pluginResp); pe != nil {
		return pluginErrorResult(pe)
	}
	f.firePostResponse(dto.policies, dto.plan, dto.request, pluginResp)
	f.recordSession(ctx, dto.request, providerResp.ResponseID, dto.backend.Provider(), providerResp.Model, providerResp.StatusCode)
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
	pluginResp.Headers = cloneHeaders(dto.baseHeaders)
	mergeProviderResponse(pluginResp, providerResp, false)
	if pe := f.runPreResponseGated(ctx, dto.policies, dto.plan, dto.request, pluginResp); pe != nil {
		return pluginErrorResult(pe), pe
	}
	f.firePostResponse(dto.policies, dto.plan, dto.request, pluginResp)
	f.recordSession(ctx, dto.request, providerResp.ResponseID, dto.backend.Provider(), providerResp.Model, providerResp.StatusCode)
	return &ForwardResult{
		StatusCode: pluginResp.StatusCode,
		Headers:    pluginResp.Headers,
		Body:       pluginResp.Body,
	}, nil
}

func (f *forwarder) loadBalancerFor(rc *appconsumer.RoutableConsumer) (*loadbalancer.LoadBalancer, error) {
	key := loadBalancerCacheKey(rc.Consumer.GatewayID, rc.Consumer.ID)
	return f.cachedOrBuildLoadBalancer(key, func() loadbalancer.Pool {
		lbAlgorithm, embeddingConfig := lbSettings(rc)
		return loadbalancer.Pool{
			ID:              key,
			Registries:      rc.Registries,
			Weights:         rc.Consumer.RegistryWeights,
			Algorithm:       lbAlgorithm,
			EmbeddingConfig: embeddingConfig,
		}
	})
}

func (f *forwarder) poolLoadBalancerFor(
	rc *appconsumer.RoutableConsumer,
	alias string,
	candidates *routingdomain.CandidateSet,
) (*loadbalancer.LoadBalancer, error) {
	key := poolLoadBalancerCacheKey(rc.Consumer.GatewayID, rc.Consumer.ID, alias)
	return f.cachedOrBuildLoadBalancer(key, func() loadbalancer.Pool {
		lbAlgorithm, embeddingConfig := lbSettings(rc)
		return loadbalancer.Pool{
			ID:              key,
			Registries:      candidates.Registries(),
			Weights:         rc.Consumer.RegistryWeights,
			Algorithm:       lbAlgorithm,
			EmbeddingConfig: embeddingConfig,
		}
	})
}

func lbSettings(rc *appconsumer.RoutableConsumer) (string, *domain.EmbeddingConfig) {
	lbAlgorithm := algorithm.RoundRobin
	var embeddingConfig *domain.EmbeddingConfig
	if lbCfg := rc.Consumer.LBConfig; lbCfg != nil && lbCfg.Enabled {
		if lbCfg.Algorithm != "" {
			lbAlgorithm = lbCfg.Algorithm
		}
		embeddingConfig = lbCfg.EmbeddingConfig
	}
	return lbAlgorithm, embeddingConfig
}

func (f *forwarder) cachedOrBuildLoadBalancer(
	key string,
	buildPool func() loadbalancer.Pool,
) (*loadbalancer.LoadBalancer, error) {
	if lb, ok := f.cachedLoadBalancer(key); ok {
		return lb, nil
	}
	built, err, _ := f.lbGroup.Do(key, func() (interface{}, error) {
		if lb, ok := f.cachedLoadBalancer(key); ok {
			return lb, nil
		}
		lb, err := loadbalancer.NewLoadBalancer(f.factory, buildPool(), f.logger, f.cache)
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

func loadBalancerCacheKey(gatewayID ids.GatewayID, consumerID ids.ConsumerID) string {
	return gatewayID.String() + ":" + consumerID.String()
}

func poolLoadBalancerCacheKey(gatewayID ids.GatewayID, consumerID ids.ConsumerID, alias string) string {
	return gatewayID.String() + ":" + consumerID.String() + ":pool:" + strings.ToLower(alias)
}
