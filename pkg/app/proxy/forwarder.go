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
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/http"
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
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

var (
	ErrNoBackendAvailable     = errors.New("no backend available")
	ErrNoBackendsInPool       = errors.New("consumer has no registries in pool")
	ErrCapabilityNotSupported = errors.New("provider does not support this capability")
	// ErrAmbiguousRequestBody refuses a chat request whose body
	// adapter.HasAmbiguousKeys reports: one that is not valid JSON, starts
	// with a byte order mark, repeats a key, or has two keys the decoder
	// reads as one struct field. The plugins would judge what the decoder
	// reads, and the upstream may read another body or another copy.
	ErrAmbiguousRequestBody = errors.New("request body is not valid JSON, repeats a key, or has keys that differ only in case where the gateway decodes it")
)

type ForwardInput struct {
	GatewayID ids.GatewayID
	Consumer  *appconsumer.RoutableConsumer
	Data      *appconsumer.Data
	Request   *infracontext.RequestContext
	Resolved  *ResolvedRouting
	RouteSlug string
	// Prechecked reports that the caller already ran Precheck on Request, so
	// Forward neither refuses an ambiguous body nor charges the plan limit a
	// second time.
	Prechecked bool
}

type ForwardResult struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	Stream     iter.Seq2[[]byte, error]
	// StreamSettled, read once Stream has returned, gives a channel closed
	// when the upstream read Stream left running in the background is done,
	// or nil when it left none. A stream guard cut leaves one: the drain that
	// reads the rest of the upstream so its usage is still charged. The
	// caller keeps the forward context alive until then.
	StreamSettled func() <-chan struct{}
	// Upstream marks a response that is exactly what the provider answered,
	// status, body and stream alike. The handler uses it to leave a native
	// Bedrock answer, AWS errors included, as AWS sent it, and to put the AWS
	// error envelope on every other error the gateway makes itself.
	Upstream bool
	// RawFrames and StreamView carry ProviderResponse's, for a native Bedrock
	// eventstream: Stream yields whole frames the handler writes with no
	// separator, and StreamView turns one into the lines metrics capture.
	RawFrames  bool
	StreamView func(frame []byte) [][]byte
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
	routeSlug   string
}

//go:generate mockery --name=Forwarder --dir=. --output=./mocks --filename=forwarder_mock.go --case=underscore --with-expecter
type Forwarder interface {
	Forward(ctx context.Context, in ForwardInput) (*ForwardResult, error)
	Precheck(ctx context.Context, gatewayID ids.GatewayID, req *infracontext.RequestContext) (*ForwardResult, error)
}

var _ Forwarder = (*forwarder)(nil)

type forwarder struct {
	balancers  *loadBalancerCache
	invoker    ProviderInvoker
	executor   appplugins.Executor
	sessions   appsession.Store
	pipeline   candidatePipeline
	limiter    ratelimitapp.Checker
	codec      guardCodec
	models     appcatalog.BedrockModelResolver
	masker     NativeBodyMasker
	maxRetries int

	nativeToolHold   time.Duration
	nativeLookupWait time.Duration
	logger           *slog.Logger
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

// WithForwarderBedrockModelResolver lets the forwarder name the model behind an
// opaque Bedrock ARN before the pre_request stage, so a cost cap and the token
// budgets see it on the first call.
func WithForwarderBedrockModelResolver(models appcatalog.BedrockModelResolver) ForwarderOption {
	return func(f *forwarder) { f.models = models }
}

// WithNativeMasker replaces how a mask is carried onto a native Bedrock body.
// It exists for tests that need a patcher that fails.
func WithNativeMasker(masker NativeBodyMasker) ForwarderOption {
	return func(f *forwarder) { f.masker = masker }
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
		pipeline:   candidatePipeline{resolver: resolver, listing: listing, logger: logger},
		limiter:    limiter,
		masker:     adapter.NativeMasker{},
		maxRetries: maxRetriesFromConfig(cfg),

		nativeToolHold:   nativeToolHoldFromConfig(cfg),
		nativeLookupWait: nativeLookupWaitFromConfig(cfg),
		logger:           logger,
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

func nativeToolHoldFromConfig(cfg *config.Config) time.Duration {
	if cfg == nil || cfg.BedrockNative.ToolHold <= 0 {
		return config.DefaultBedrockNative().ToolHold
	}
	return cfg.BedrockNative.ToolHold
}

func nativeLookupWaitFromConfig(cfg *config.Config) time.Duration {
	if cfg == nil || cfg.BedrockNative.LookupWait <= 0 {
		return config.DefaultBedrockNative().LookupWait
	}
	return cfg.BedrockNative.LookupWait
}

func (f *forwarder) Forward(ctx context.Context, in ForwardInput) (*ForwardResult, error) {
	if in.Consumer == nil || in.Consumer.Consumer == nil {
		return nil, ErrNoBackendsInPool
	}
	if !in.Prechecked {
		if result, err := f.Precheck(ctx, in.GatewayID, in.Request); result != nil || err != nil {
			return result, err
		}
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
	_, in.Request.DefaultModel = routePolicy(candidates, in.Consumer, route.route)
	f.resolveOpaqueNativeModel(ctx, route.route.Registry, in.Request)
	resp := &infracontext.ResponseContext{
		GatewayID:  in.Request.GatewayID,
		RegistryID: in.Request.RegistryID,
	}
	policies := in.Consumer.Policies
	plan := in.Consumer.PolicyPlan

	nativeBody := nativeBodySnapshot(in.Request)
	if nativeBody != nil {
		in.Request.NativeMask = &infracontext.NativeMaskLog{}
	}
	if short, err := f.runPreRequest(ctx, policies, plan, in.Request, resp); err != nil {
		return nil, err
	} else if short != nil {
		return nativeShortCircuit(in.Request, short, policydomain.StagePreRequest), nil
	}
	if nativeBody != nil && !bytes.Equal(nativeBody, in.Request.Body) {
		masked, pe := f.carryNativeMask(ctx, policydomain.StagePreRequest, in.Request, nativeBody, in.Request.Body, f.masker.MaskRequestWhy)
		if pe != nil {
			return pluginErrorResult(pe), nil
		}
		in.Request.Body = masked
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
		routeSlug:   cmp.Or(in.RouteSlug, in.Consumer.Consumer.Slug),
	}
	stream := DetectStream(dto.request)

	return f.invokeWithFailover(ctx, in.Consumer, dto, stream, route)
}

// ambiguousChatBody reports a chat request whose body the decoder may read
// otherwise than the upstream. It runs before routing and before any plugin.
// Only chat bodies are checked: the tool and prompt plugins judge them
// through the canonical decode, whose struct shapes HasAmbiguousKeys knows.
func ambiguousChatBody(req *infracontext.RequestContext) bool {
	if req == nil || len(req.Body) == 0 {
		return false
	}
	if req.IsBedrockNative() {
		if adapter.BedrockNativeOp(req.BedrockNative.Op).IsConverse() {
			return adapter.HasAmbiguousKeys(adapter.FormatBedrock, req.Body)
		}
		return adapter.HasAmbiguousInvokeKeys(req.Body)
	}
	format := sourceFormatFromRequest(req)
	return adapter.IsChatRequest(req.ProxyCapability, format) && adapter.HasAmbiguousKeys(format, req.Body)
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
	var misses []modelMiss
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

			dto.request.NativeMask.Reset(policydomain.StagePreResponse)
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
					if sequential {
						misses = append(misses, newModelMiss(bk, resp))
					}
					break
				}
				if sequential && (responseCarriesModelNotFound(resp) || nativeAccessDenied(dto.request, resp)) {
					last = failoverState{resp: resp}
					lastKind = failureNone
					misses = append(misses, newModelMiss(bk, resp))
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
		// A native Bedrock caller is talking to AWS, and AWS's own answer to an
		// unknown model identifier is the error its SDK knows how to read: the
		// status, the x-amzn-ErrorType and the request id. Every registry was
		// probed, so the last answer is relayed as it came instead of being
		// replaced by a gateway 404 the SDK cannot classify.
		if dto.request.IsBedrockNative() && last.resp != nil {
			return f.finalizeBody(ctx, dto, last.resp), nil
		}
		return nil, noRegistryServesModelError(dto.request.RequestedModel, dto.routeSlug, route.chain, misses)
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
	if lb != nil {
		if next, err := lb.NextRoute(ctx, req, excluded); err == nil && next != nil {
			if _, seen := excluded[next.Key()]; !seen {
				return next, false
			}
		}
		if lb.Algorithm() == algorithm.SmartRouting {
			return nil, false
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
	req.PreviousResponseID = f.sessions.LastTurnID(ctx, sessionScope(req), req.SessionID)
}

func sessionScope(req *infracontext.RequestContext) appsession.Scope {
	return appsession.Scope{GatewayID: req.GatewayID, OwnerID: req.OwnerID}
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
		Scope:     sessionScope(req),
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
	native := dto.request.IsBedrockNative()
	mergeStreamingResponse(pluginResp, providerResp)
	outcome, pe := f.runPreResponseGated(ctx, dto.policies, dto.plan, dto.request, pluginResp)
	if pe != nil {
		f.drainAsync(providerResp.Stream)
		return pluginErrorResult(pe)
	}
	if outcome != nil && outcome.ShortCircuit {
		f.drainAsync(providerResp.Stream)
		return nativeShortCircuit(dto.request, f.shortCircuitStream(ctx, dto, providerResp, pluginResp, outcome), policydomain.StagePreResponse)
	}
	stream := providerResp.Stream
	var cutBarrier func() <-chan struct{}
	var wasCut func() bool
	if guard := f.newStreamGuard(dto, pluginResp); guard != nil {
		remaining, pe := guard.Run(ctx, stream)
		if pe != nil {
			f.drainAsync(remaining)
			return pluginErrorResult(pe)
		}
		stream = remaining
		cutBarrier = guard.cutBarrier
		wasCut = guard.wasCut
	}
	stream = f.refreshModelAtStreamEnd(ctx, dto, stream)
	out := f.wrapStreamWithPostResponse(
		ctx, dto.policies, dto.plan, dto.request, pluginResp, stream, cutBarrier, wasCut, providerResp.StreamView)
	out = retimeSpanOnStreamEnd(out, span, startedAt)
	out = f.recordSessionOnStreamEnd(ctx, dto.request, span, providerResp.StatusCode, out)
	return &ForwardResult{
		StatusCode:    providerResp.StatusCode,
		Headers:       pluginResp.Headers,
		Stream:        out,
		StreamSettled: cutBarrier,
		Upstream:      native,
		RawFrames:     providerResp.RawFrames,
		StreamView:    providerResp.StreamView,
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

			nativeToolHold: f.nativeToolHold,
		},
		f.logger,
	)
	// A cut abandons the upstream mid-response, which is the same situation
	// drainAsync already exists for: the usage the last chunk carries is read
	// on the way through adaptStream, so draining is what keeps a cut stream
	// charged. post_response then orders itself behind guard.cutBarrier, which
	// is what makes "charged" true rather than aspirational.
	guard.drain = f.drainAsync
	guard.detach = f.goAsync
	if dto.request.IsBedrockNative() {
		// The same segmentation and plugin calls as an SSE stream, over frames:
		// each frame is an event, its decoded text is what is inspected, and the
		// original frame is what is released. Each policy's streaming.on_error is
		// honoured, as on every other stream.
		guard.native = true
		guard.seg.frames = true
	}
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

// goAsync runs fn on its own goroutine, which owns its panic: a panic is
// recovered and logged rather than crashing the process.
func (f *forwarder) goAsync(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				f.logger.Error("panic in detached stream work", slog.Any("panic", r))
			}
		}()
		fn()
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
	native := dto.request.IsBedrockNative()
	if native && nativeResponseChanged(providerResp, pluginResp) {
		errorResponse := providerResp.StatusCode >= http.StatusMultipleChoices &&
			len(dto.request.NativeMask.Sources(policydomain.StagePreResponse)) > 0
		if !errorResponse && pluginResp.StatusCode != providerResp.StatusCode {
			pe := appplugins.WithBlockDirection(nativeModified(nativeResponseModified), appplugins.BlockDirectionOutput)
			return pluginErrorResult(pe), pe
		}
		maskResponse := f.masker.MaskResponseWhy
		if errorResponse {
			maskResponse = func(_, _ []byte) ([]byte, adapter.MaskCause) {
				return nil, adapter.MaskCauseErrorResponse
			}
		}
		masked, pe := f.carryNativeMask(ctx, policydomain.StagePreResponse, dto.request, providerResp.Body, pluginResp.Body, maskResponse)
		if pe != nil {
			return pluginErrorResult(pe), pe
		}
		pluginResp.Body = masked
		pluginResp.StatusCode = providerResp.StatusCode
	}
	f.firePostResponse(ctx, dto.policies, dto.plan, dto.request, pluginResp)
	f.recordSession(ctx, dto.request, providerResp.ResponseID, dto.backend.Provider(), providerResp.Model, providerResp.StatusCode)
	return &ForwardResult{
		StatusCode: pluginResp.StatusCode,
		Headers:    pluginResp.Headers,
		Body:       pluginResp.Body,
		Upstream:   native,
	}, nil
}
