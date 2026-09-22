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
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
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
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

var (
	ErrNoBackendAvailable     = errors.New("no backend available")
	ErrNoBackendsInPool       = errors.New("consumer has no registries in pool")
	ErrCapabilityNotSupported = errors.New("provider does not support this capability")
)

type ForwardInput struct {
	GatewayID ids.GatewayID
	Consumer  *appconsumer.RoutableConsumer
	Data      *appconsumer.Data
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
	baseline    *trace.RouteBaseline
	tierRouted  bool
}

//go:generate mockery --name=Forwarder --dir=. --output=./mocks --filename=forwarder_mock.go --case=underscore --with-expecter
type Forwarder interface {
	Forward(ctx context.Context, in ForwardInput) (*ForwardResult, error)
}

var _ Forwarder = (*forwarder)(nil)

type forwarder struct {
	balancers  *loadBalancerCache
	invoker    ProviderInvoker
	executor   appplugins.Executor
	sessions   appsession.Store
	resolver   approuting.Resolver
	listing    appcatalog.ModelListing
	limiter    ratelimitapp.Checker
	codec      guardCodec
	maxRetries int
	logger     *slog.Logger
}

// ForwarderOption configures an optional forwarder capability.
type ForwarderOption func(*forwarder)

// WithStreamCodec attaches the codec the stream guard segments SSE events
// with. Omitting it leaves the guard unbuilt, which is what keeps tests that do
// not exercise streaming inspection off the path entirely.
func WithStreamCodec(codec guardCodec) ForwarderOption {
	return func(f *forwarder) {
		f.codec = codec
	}
}

// NewForwarder builds the proxy forwarder; nil limiter defaults to noop.
func NewForwarder(
	factory loadbalancer.Factory,
	cacheClient loadbalancer.RedisProvider,
	manager *cache.TTLMapManager,
	invoker ProviderInvoker,
	executor appplugins.Executor,
	sessions appsession.Store,
	resolver approuting.Resolver,
	listing appcatalog.ModelListing,
	limiter ratelimitapp.Checker,
	cfg *config.Config,
	logger *slog.Logger,
	opts ...ForwarderOption,
) Forwarder {
	if limiter == nil {
		limiter = ratelimitapp.NewNoopChecker()
	}
	fwd := &forwarder{
		balancers:  newLoadBalancerCache(factory, cacheClient, manager.GetTTLMap(cache.LoadBalancerTTLName), logger),
		invoker:    invoker,
		executor:   executor,
		sessions:   sessions,
		resolver:   resolver,
		listing:    listing,
		limiter:    limiter,
		maxRetries: maxRetriesFromConfig(cfg),
		logger:     logger,
	}
	for _, opt := range opts {
		opt(fwd)
	}
	return fwd
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

	if result, err := f.checkRateLimit(ctx, in.GatewayID); result != nil || err != nil {
		return result, err
	}

	intent, candidates, err := f.resolveRouting(ctx, in)
	if err != nil {
		return nil, err
	}
	applyIntentToBody(in.Request, intent)

	f.stampConsumerScope(in)
	f.stampContinuation(ctx, in.Request)

	route, err := f.routeBackend(ctx, in.Consumer, in.Request, intent, candidates)
	if err != nil {
		return nil, err
	}

	stampTarget(in.Request, route.route.Registry)
	resp := &infracontext.ResponseContext{
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
		backend:     route.route.Registry,
		candidates:  candidates,
		pinned:      route.pinned,
		request:     in.Request,
		response:    resp,
		policies:    policies,
		plan:        plan,
		baseHeaders: cloneHeaders(resp.Headers),
		baseline:    route.baseline,
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
		excluded = make(map[routingdomain.RouteKey]struct{})
	}

	last := failoverState{}
	lastKind := failureNone
	current := route.route
	fromFallback := route.fromFallback
	sequential := len(route.chain) > 0
	modelMissOnly := sequential
	for current.Registry != nil {
		bk := current.Registry
		f.retarget(dto, bk)
		f.stampRoutingPolicy(dto, rc, current)
		dto.tierRouted = takeTierRouted(dto.request)
		for r := 0; r < attemptsPerBackend; r++ {
			selectingRegistry := sequential && modelMissOnly
			if selectingRegistry && budget.deadlineExceeded() {
				return f.relayLast(ctx, dto, last)
			}
			if !selectingRegistry && budget.exhausted() {
				return f.relayLast(ctx, dto, last)
			}
			budget.recordAttempt()

			startedAt := time.Now()
			resp, err := f.invokeOnce(ctx, bk, dto.request, stream)
			elapsed := time.Since(startedAt)
			outcome := classifyOutcome(resp, err, triggers)
			span := f.recordSpan(ctx, dto, current, fromFallback, budget.attempts, outcome, resp, elapsed)
			switch outcome {
			case OutcomeSuccess:
				reportSuccess(lb, bk)
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

				modelMissOnly = false
				last = failoverState{rejection: result}
				lastKind = failurePluginRejection
				f.logRetry(bk, pe, budget)
			case OutcomeTerminal:
				if resp == nil {
					return nil, err
				}
				if !route.pinned && filesIDNotFound(dto.request, resp) {
					last = failoverState{resp: resp}
					lastKind = failureNone
					break
				}
				if sequential && responseCarriesModelNotFound(resp) {
					last = failoverState{resp: resp}
					lastKind = failureNone
					break
				}
				reportSuccess(lb, bk)
				return f.finalizeBody(ctx, dto, resp), nil
			case OutcomeRetryable:
				modelMissOnly = false
				reason := failureReason(resp, err)
				reportFailure(ctx, lb, bk, reason)
				last = failoverState{resp: resp, err: err}
				lastKind = classifyFailure(resp, err)
				f.logRetry(bk, reason, budget)
				continue
			}
			break
		}
		excluded[current.Key()] = struct{}{}
		if route.pinned {
			break
		}
		next, viaFallback := f.nextCandidate(
			ctx, lb, rc, dto.request, route.chain, excluded, triggers.allowsFallback(lastKind))
		if next == nil {
			break
		}
		current, fromFallback = *next, viaFallback
	}

	if sequential && modelMissOnly && budget.attempts > 0 {
		return nil, noRegistryServesModelError(dto.request.RequestedModel, route.chain, last)
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
	ctx context.Context,
	lb *loadbalancer.LoadBalancer,
	rc *appconsumer.RoutableConsumer,
	req *infracontext.RequestContext,
	chain []routingdomain.Route,
	excluded map[routingdomain.RouteKey]struct{},
	allowChain bool,
) (*routingdomain.Route, bool) {
	if len(chain) > 0 {
		return nextChainRoute(chain, excluded), false
	}
	if len(chain) > 0 {
		return nextChainRoute(chain, excluded), false
	}
	if lb != nil {
		if next, err := lb.NextRoute(ctx, req, excluded); err == nil && next != nil {
			if _, seen := excluded[next.Key()]; !seen {
				return next, false
			}
		}
	}
	if !allowChain {
		return nil, false
	}
	if bk := firstAvailableFallback(rc, excluded); bk != nil {
		fallback := routingdomain.RouteForRegistry(bk)
		return &fallback, true
	}
	return nil, false
}

func reportSuccess(lb *loadbalancer.LoadBalancer, bk *domain.Registry) {
	if lb != nil {
		lb.ReportSuccess(bk)
	}
}

func reportFailure(ctx context.Context, lb *loadbalancer.LoadBalancer, bk *domain.Registry, reason error) {
	if lb != nil {
		lb.ReportFailure(ctx, bk, reason)
	}
}

func (f *forwarder) recordSpan(
	ctx context.Context,
	dto *forwardRequestDTO,
	route routingdomain.Route,
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
	bk := route.Registry
	span := &trace.Span{
		Type:      trace.SpanLLM,
		Name:      bk.Provider(),
		StartedAt: time.Now().Add(-elapsed),
		LLM: &trace.LLMAttrs{
			RegistryID:     bk.ID.String(),
			Provider:       bk.Provider(),
			RouteModel:     route.Model,
			RequestedModel: dto.request.RequestedModel,
			Attempt:        attempt,
			Fallback:       fromFallback,
			Pinned:         dto.pinned,
			Route:          dto.routeSource,
			Outcome:        outcome.String(),
			Baseline:       dto.baseline,
			ServedPricing:  bk.Pricing(),
			TierApplied:    dto.tierRouted,
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
	in.Request.ConsumerType = string(in.Consumer.Consumer.Type)
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

func takeTierRouted(req *infracontext.RequestContext) bool {
	if req == nil || req.RoutingDecision == nil {
		return false
	}
	tierRouted := req.RoutingDecision.TierApplied
	req.RoutingDecision = nil
	return tierRouted
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
	req.RegistryPricing = bk.Pricing()
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
	mergeStreamingResponse(pluginResp, providerResp)
	outcome, pe := f.runPreResponseGated(ctx, dto.policies, dto.plan, dto.request, pluginResp)
	if pe != nil {
		f.drainAsync(providerResp.Stream)
		return pluginErrorResult(pe)
	}
	if outcome != nil && outcome.ShortCircuit {
		f.drainAsync(providerResp.Stream)
		return f.shortCircuitStream(ctx, dto, providerResp, pluginResp, outcome)
	}
	stream := providerResp.Stream
	var cutBarrier func() <-chan struct{}
	if guard := f.newStreamGuard(dto, pluginResp); guard != nil {
		remaining, pe := guard.Run(ctx, stream)
		if pe != nil {
			f.drainAsync(remaining)
			return pluginErrorResult(pe)
		}
		stream = remaining
		cutBarrier = guard.cutBarrier
	}
	out := f.wrapStreamWithPostResponse(ctx, dto.policies, dto.plan, dto.request, pluginResp, stream, cutBarrier)
	out = retimeSpanOnStreamEnd(out, span, startedAt)
	out = f.recordSessionOnStreamEnd(ctx, dto.request, span, providerResp.StatusCode, out)
	return &ForwardResult{
		StatusCode: providerResp.StatusCode,
		Headers:    pluginResp.Headers,
		Stream:     out,
	}
}

// shortCircuitStream renders a pre_response stop on the streaming leg. What it
// returns is a buffered response — a status, headers and a body, with no stream
// behind it — so it runs the two tails finalizeBodyGated runs after its own
// short circuit. Without them a plugin-stopped streamed response would be
// invisible to post_response auditing and to session recording while the
// identical buffered response is not, which is an asymmetry nothing downstream
// could explain.
//
// The headers cannot be the ones the outcome carries. They were cloned from the
// provider's streaming response, and text/event-stream in front of a plugin's
// body is a content type the body does not have: an SSE client reads it as a
// stream that never yields an event and never ends. Content-Type is replaced
// for the same reason pluginErrorResult sets it, and Transfer-Encoding goes
// with it because it described a response that is no longer being sent.
func (f *forwarder) shortCircuitStream(
	ctx context.Context,
	dto *forwardRequestDTO,
	providerResp *ProviderResponse,
	pluginResp *infracontext.ResponseContext,
	outcome *appplugins.StageOutcome,
) *ForwardResult {
	// The response leg is no longer streaming, and saying so is what lets
	// post_response read the body: every output-inspecting plugin skips a
	// response marked streaming, because on that leg the body is empty by
	// construction. Here it is not — it is whatever the plugin handed back.
	pluginResp.Streaming = false
	f.firePostResponse(ctx, dto.policies, dto.plan, dto.request, pluginResp)
	f.recordSession(
		ctx, dto.request, providerResp.ResponseID,
		dto.backend.Provider(), providerResp.Model, providerResp.StatusCode,
	)
	headers := cloneResponseHeaders(outcome.Headers)
	deleteResponseHeader(headers, "Transfer-Encoding")
	if len(outcome.Body) > 0 {
		setResponseHeader(headers, "Content-Type", "application/json")
	}
	return &ForwardResult{
		StatusCode: outcome.StatusCode,
		Headers:    headers,
		Body:       outcome.Body,
	}
}

// newStreamGuard builds the head gate, and returns nil when no policy enabled
// per-segment inspection. A gateway whose policies do not participate keeps the
// streaming path it has today: not a wrapper that passes through, no wrapper at
// all, so not one extra allocation or indirection sits between the provider and
// the client.
//
// head_chars, on_error and the block-loop knobs come from StreamPlan rather
// than from a literal, so a policy that sets on_error to fail_closed is not
// silently run as fail_open.
func (f *forwarder) newStreamGuard(
	dto *forwardRequestDTO,
	resp *infracontext.ResponseContext,
) *streamGuard {
	if f.executor == nil || f.codec == nil {
		return nil
	}
	enabled, opts := dto.plan.StreamPlan(policydomain.StagePreResponse)
	if !enabled {
		return nil
	}
	runner, ok := f.executor.(segmentRunner)
	if !ok {
		return nil
	}
	guard := newStreamGuard(
		runner,
		f.codec,
		sourceFormatFromRequest(dto.request),
		appplugins.StageInput{
			Stage:    policydomain.StagePreResponse,
			Policies: dto.policies,
			Plan:     dto.plan,
			Request:  dto.request,
			Response: resp,
		},
		streamGuardConfig{
			headChars:     opts.HeadChars,
			onError:       streamOnError(opts.OnError),
			minChars:      opts.MinCharsBetweenEvals,
			maxHold:       time.Duration(opts.MaxHoldMS) * time.Millisecond,
			maxAccumBytes: opts.MaxAccumulatedBytes,
		},
		f.logger,
	)
	// A cut abandons the upstream mid-response, which is the same situation
	// drainAsync already exists for: the usage the last chunk carries is read
	// on the way through adaptStream, so draining is what keeps a cut stream
	// charged. post_response then orders itself behind guard.cutBarrier, which
	// is what makes "charged" true rather than aspirational.
	guard.drain = f.drainAsync
	return guard
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

// drainAsync drains an abandoned provider stream in the background so the
// backend connection is released. The goroutine owns its panic: a drain panic
// is recovered and logged rather than crashing the process.
func (f *forwarder) drainAsync(stream iter.Seq2[[]byte, error]) {
	if stream == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				f.logger.Error("panic draining abandoned provider stream", slog.Any("panic", r))
			}
		}()
		drainStream(stream)
	}()
}

func (f *forwarder) finalizeBody(
	ctx context.Context,
	dto *forwardRequestDTO,
	providerResp *ProviderResponse,
) *ForwardResult {
	result, _ := f.finalizeBodyGated(ctx, dto, providerResp)
	return result
}

func (f *forwarder) finalizeBodyGated(
	ctx context.Context,
	dto *forwardRequestDTO,
	providerResp *ProviderResponse,
) (*ForwardResult, *appplugins.PluginError) {
	pluginResp := dto.response
	pluginResp.Headers = cloneHeaders(dto.baseHeaders)
	mergeBufferedResponse(pluginResp, providerResp)
	if _, pe := f.runPreResponseGated(ctx, dto.policies, dto.plan, dto.request, pluginResp); pe != nil {
		return pluginErrorResult(pe), pe
	}
	f.firePostResponse(ctx, dto.policies, dto.plan, dto.request, pluginResp)
	f.recordSession(ctx, dto.request, providerResp.ResponseID, dto.backend.Provider(), providerResp.Model, providerResp.StatusCode)
	return &ForwardResult{
		StatusCode: pluginResp.StatusCode,
		Headers:    pluginResp.Headers,
		Body:       pluginResp.Body,
	}, nil
}
