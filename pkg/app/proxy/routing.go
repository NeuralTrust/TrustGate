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
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/modelmatch"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

type routedBackend struct {
	lb           *loadbalancer.LoadBalancer
	route        routingdomain.Route
	chain        []routingdomain.Route
	excluded     map[routingdomain.RouteKey]struct{}
	fromFallback bool
	pinned       bool
	baseline     *trace.RouteBaseline
}

type CandidateFilter func(routingdomain.Candidate) bool

type ResolvedRouting struct {
	Intent     routingdomain.Intent
	Ref        string
	Candidates *routingdomain.CandidateSet
}

var errNoKeptCandidate = fmt.Errorf("no candidate survives the store scope: %w", routingdomain.ErrModelDenied)

type candidateQuery struct {
	intent        routingdomain.Intent
	needed        string
	consumer      *appconsumer.RoutableConsumer
	data          *appconsumer.Data
	request       *infracontext.RequestContext
	keep          CandidateFilter
	strictListing bool
}

type candidatePipeline struct {
	resolver approuting.Resolver
	listing  appcatalog.ModelListing
	logger   *slog.Logger
}

func (f *forwarder) resolveRouting(
	ctx context.Context,
	in ForwardInput,
) (routingdomain.Intent, *routingdomain.CandidateSet, error) {
	if in.Resolved != nil {
		in.Request.RequestedModel = in.Resolved.Ref
		candidates, err := keepCandidates(in.Resolved.Candidates, in.Keep)
		return in.Resolved.Intent, candidates, err
	}
	intent, ref, err := parseIntent(in.Request)
	if err != nil {
		f.logRejectedIntent(in.Consumer, ref, err)
		return intent, nil, err
	}
	in.Request.RequestedModel = ref
	needed := capabilityRequiresProviderSupport(in.Request)
	if intent.IsZero() && needed == "" && in.Keep == nil {
		return intent, nil, nil
	}
	candidates, err := f.pipeline.run(ctx, candidateQuery{
		intent:   intent,
		needed:   needed,
		consumer: in.Consumer,
		data:     in.Data,
		request:  in.Request,
		keep:     in.Keep,
	})
	if err != nil {
		f.logRejectedIntent(in.Consumer, ref, err)
		return intent, nil, err
	}
	return intent, candidates, nil
}

func (p candidatePipeline) run(ctx context.Context, q candidateQuery) (*routingdomain.CandidateSet, error) {
	candidates, err := p.resolver.Resolve(approuting.ResolveInput{
		Intent:     q.intent,
		Consumer:   q.consumer,
		Registries: registryLookup(q.data),
	})
	if err != nil {
		return nil, err
	}
	if candidates, err = keepCandidates(candidates, q.keep); err != nil {
		return nil, err
	}
	if q.needed != "" {
		capable := filterCandidatesByCapability(candidates, q.needed)
		if capable.Len() == 0 && candidates.Len() > 0 {
			return nil, fmt.Errorf("%w: %s", ErrCapabilityNotSupported, q.needed)
		}
		candidates = capable
	}
	if q.needed == capabilityFiles {
		candidates = filterCandidatesByFilesID(candidates, q.request)
	}
	if candidates.Len() == 0 {
		return nil, ErrNoBackendsInPool
	}
	if q.intent.IsShortModel() {
		candidates = p.filterCandidatesByProviderListing(ctx, candidates, q.intent.Model, q.strictListing)
	}
	return candidates, nil
}

func keepCandidates(candidates *routingdomain.CandidateSet, keep CandidateFilter) (*routingdomain.CandidateSet, error) {
	if keep == nil {
		return candidates, nil
	}
	kept := candidates.Filter(keep)
	if kept.Len() == 0 {
		return nil, errNoKeptCandidate
	}
	return kept, nil
}

func (p candidatePipeline) filterCandidatesByProviderListing(
	ctx context.Context,
	candidates *routingdomain.CandidateSet,
	model string,
	strict bool,
) *routingdomain.CandidateSet {
	if p.listing == nil {
		return candidates
	}
	served := candidates.Filter(func(c routingdomain.Candidate) bool {
		if c.Registry == nil {
			return false
		}
		if !c.DefersModelChoice() {
			return true
		}
		if p.listing.Lists(ctx, c.Registry.Provider(), model) != appcatalog.VerdictAbsent {
			return true
		}
		p.logSkippedRegistry(c.Registry, model)
		return false
	})
	if served.Len() == 0 && !strict {
		return candidates
	}
	return served
}

func (p candidatePipeline) logSkippedRegistry(reg *domain.Registry, model string) {
	if p.logger == nil {
		return
	}
	p.logger.Debug("registry skipped: provider catalog does not list model",
		slog.String("registry_id", reg.ID.String()),
		slog.String("provider", reg.Provider()),
		slog.String("model", model),
	)
}

func capabilityRequiresProviderSupport(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	switch req.ProxyCapability {
	case capabilityEmbeddings, capabilityRerank, capabilityFiles, capabilityImages,
		capabilityAudioSpeech, capabilityAudioTranscription:
		return req.ProxyCapability
	default:
		return ""
	}
}

func isAudioCapability(capability string) bool {
	return capability == capabilityAudioSpeech || capability == capabilityAudioTranscription
}

func filterCandidatesByCapability(candidates *routingdomain.CandidateSet, capability string) *routingdomain.CandidateSet {
	return candidates.Filter(func(c routingdomain.Candidate) bool {
		if c.Registry == nil {
			return false
		}
		return providers.SupportsCapability(c.Registry.Provider(), capability)
	})
}

func filterCandidatesByFilesID(candidates *routingdomain.CandidateSet, req *infracontext.RequestContext) *routingdomain.CandidateSet {
	if req == nil {
		return candidates
	}
	fileID := providers.FilesIDFromPath(req.Path)
	if fileID == "" {
		return candidates
	}
	return candidates.Filter(func(c routingdomain.Candidate) bool {
		if c.Registry == nil {
			return false
		}
		return providers.ProviderMatchesFilesID(c.Registry.Provider(), fileID)
	})
}

func filesIDNotFound(req *infracontext.RequestContext, resp *ProviderResponse) bool {
	if req == nil || resp == nil || req.ProxyCapability != capabilityFiles {
		return false
	}
	if providers.FilesIDFromPath(req.Path) == "" {
		return false
	}
	return resp.StatusCode == http.StatusNotFound
}

func (f *forwarder) logRejectedIntent(rc *appconsumer.RoutableConsumer, ref string, err error) {
	if f.logger == nil {
		return
	}
	consumerID := ""
	if rc != nil && rc.Consumer != nil {
		consumerID = rc.Consumer.ID.String()
	}
	f.logger.Debug("routing intent rejected",
		slog.String("consumer_id", consumerID),
		slog.String("intent", ref),
		slog.String("reason", err.Error()),
	)
}

func parseIntent(req *infracontext.RequestContext) (routingdomain.Intent, string, error) {
	if req == nil {
		return routingdomain.Intent{}, "", nil
	}
	ref, err := modelRefFromRequest(req)
	if err != nil {
		return routingdomain.Intent{}, "", err
	}
	intent, err := routingdomain.ParseModelRef(ref)
	return intent, strings.TrimSpace(ref), err
}

func modelRefFromRequest(req *infracontext.RequestContext) (string, error) {
	if adapter.Format(req.SourceFormat) == adapter.FormatGemini {
		return adapter.GeminiModelFromPath(req.Path), nil
	}
	if len(req.Body) == 0 {
		return "", nil
	}
	ref, hasModelID, err := adapter.ExtractModelField(req.Body)
	if err != nil {
		if req.ProxyCapability == capabilityImages && providers.IsImagesMultipart(req.HeaderValue(headerContentType)) {
			return providers.ExtractImagesModel(req.HeaderValue(headerContentType), req.Body), nil
		}
		if isAudioCapability(req.ProxyCapability) && providers.IsAudioMultipart(req.HeaderValue(headerContentType)) {
			return providers.ExtractAudioModel(req.HeaderValue(headerContentType), req.Body), nil
		}
		return "", nil
	}
	if hasModelID {
		return "", fmt.Errorf(
			"%w: modelId is not a supported request field, use the model field", routingdomain.ErrInvalidModelRef)
	}
	return ref, nil
}

func applyIntentToBody(req *infracontext.RequestContext, intent routingdomain.Intent) {
	if req == nil {
		return
	}
	if intent.IsAuto() {
		req.Body = adapter.StripModel(req.Body)
		return
	}
	if intent.IsZero() {
		return
	}
	if intent.IsPool() {
		req.Body = adapter.StripModel(req.Body)
		return
	}
	if intent.IsQualified() {
		req.Body = adapter.OverrideModel(req.Body, intent.Model)
		return
	}
	// Gemini clients send the model in the path, not the body; stamp it so
	// adapters and the upstream client can resolve it.
	if intent.IsShortModel() && adapter.Format(req.SourceFormat) == adapter.FormatGemini {
		req.Body = adapter.OverrideModel(req.Body, intent.Model)
	}
}

func registryLookup(data *appconsumer.Data) approuting.RegistryLookup {
	if data == nil {
		return nil
	}
	return data.RegistryByID
}

func (f *forwarder) routeBackend(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	req *infracontext.RequestContext,
	intent routingdomain.Intent,
	candidates *routingdomain.CandidateSet,
) (routedBackend, error) {
	if intent.IsQualified() {
		return routedBackend{
			route:    routingdomain.RouteForRegistry(candidates.Candidates()[0].Registry),
			excluded: make(map[routingdomain.RouteKey]struct{}),
			pinned:   true,
		}, nil
	}
	if chain := candidateChain(candidates); intent.IsShortModel() && len(chain) > 0 {
		return routedBackend{
			route:    chain[0],
			chain:    chain,
			excluded: make(map[routingdomain.RouteKey]struct{}),
		}, nil
	}
	if len(rc.Registries) == 0 {
		return routedBackend{}, ErrNoBackendsInPool
	}
	lb, err := f.routeLoadBalancer(rc, intent)
	if err != nil {
		return routedBackend{}, err
	}
	excluded := nonCandidateRoutes(lb, rc, candidates)
	route, err := lb.NextRoute(ctx, req, excluded)
	baseline := smartRoutingBaseline(lb, excluded)
	if err != nil {
		if fallback := firstAvailableFallback(rc, excluded); fallback != nil {
			return routedBackend{
				lb:           lb,
				route:        routingdomain.RouteForRegistry(fallback),
				excluded:     excluded,
				fromFallback: true,
			}, nil
		}
		return routedBackend{}, fmt.Errorf("%w: %s", ErrNoBackendAvailable, err.Error())
	}
	return routedBackend{lb: lb, route: *route, excluded: excluded, baseline: baseline}, nil
}

func candidateChain(candidates *routingdomain.CandidateSet) []routingdomain.Route {
	all := candidates.Candidates()
	chain := make([]routingdomain.Route, 0, len(all))
	for _, c := range all {
		chain = append(chain, routingdomain.RouteForRegistry(c.Registry))
	}
	return chain
}

func nextChainRoute(
	chain []routingdomain.Route,
	excluded map[routingdomain.RouteKey]struct{},
) *routingdomain.Route {
	for i := range chain {
		if _, seen := excluded[chain[i].Key()]; seen {
			continue
		}
		return &chain[i]
	}
	return nil
}

const (
	maxMissDetailRunes = 200
	missWithoutDetail  = "no detail"
)

type modelMiss struct {
	provider string
	detail   string
}

func newModelMiss(bk *domain.Registry, resp *ProviderResponse) modelMiss {
	return modelMiss{
		provider: bk.Provider(),
		detail:   truncateRunes(adapter.ProviderErrorMessage(resp.Body), maxMissDetailRunes),
	}
}

// Every registry's answer is kept because after failover the last provider
// is rarely the one the caller meant (ENG-1643).
func noRegistryServesModelError(model, consumerSlug string, chain []routingdomain.Route, misses []modelMiss) error {
	err := fmt.Errorf("%w: %q (tried %s)",
		routingdomain.ErrNoRegistryServesModel, model, strings.Join(chainProviders(chain), ", "))
	if len(misses) > 0 {
		err = fmt.Errorf("%w: provider responses: %s", err, formatMisses(misses))
	}
	return fmt.Errorf("%w. List the models this application can use with GET %s", err, modelsPath(consumerSlug))
}

func modelsPath(consumerSlug string) string {
	if consumerSlug == "" {
		return "/v1/models"
	}
	return "/" + consumerSlug + "/v1/models"
}

func formatMisses(misses []modelMiss) string {
	parts := make([]string, 0, len(misses))
	for _, m := range misses {
		detail := m.detail
		if detail == "" {
			detail = missWithoutDetail
		}
		parts = append(parts, "["+m.provider+": "+detail+"]")
	}
	return strings.Join(parts, " ")
}

func truncateRunes(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit]) + "…"
}

func chainProviders(chain []routingdomain.Route) []string {
	out := make([]string, 0, len(chain))
	seen := make(map[string]struct{}, len(chain))
	for _, route := range chain {
		if route.Registry == nil {
			continue
		}
		provider := route.Registry.Provider()
		if _, dup := seen[provider]; dup {
			continue
		}
		seen[provider] = struct{}{}
		out = append(out, provider)
	}
	return out
}

func smartRoutingBaseline(
	lb *loadbalancer.LoadBalancer,
	excluded map[routingdomain.RouteKey]struct{},
) *trace.RouteBaseline {
	if lb == nil || lb.Algorithm() != algorithm.SmartRouting {
		return nil
	}
	tier, ok := lb.SmartRouting().HighestTier()
	if !ok {
		return nil
	}
	model := tier.RouteModel()
	for _, route := range lb.Routes() {
		if route.Registry == nil || route.Registry.ID != tier.RegistryID {
			continue
		}
		if model != "" && route.Model != model {
			continue
		}
		if _, skip := excluded[route.Key()]; skip {
			continue
		}
		slug := route.Model
		if slug == "" {
			slug = route.Default
		}
		if slug == "" {
			return nil
		}
		return &trace.RouteBaseline{
			Provider: route.Registry.Provider(),
			Model:    slug,
			Pricing:  route.Registry.Pricing(),
		}
	}
	return nil
}

func (f *forwarder) routeLoadBalancer(
	rc *appconsumer.RoutableConsumer,
	intent routingdomain.Intent,
) (*loadbalancer.LoadBalancer, error) {
	if intent.IsPool() {
		return f.balancers.PoolFor(rc, intent.PoolAlias)
	}
	return f.balancers.For(rc)
}

func nonCandidateRoutes(
	lb *loadbalancer.LoadBalancer,
	rc *appconsumer.RoutableConsumer,
	candidates *routingdomain.CandidateSet,
) map[routingdomain.RouteKey]struct{} {
	excluded := make(map[routingdomain.RouteKey]struct{})
	if candidates == nil {
		return excluded
	}
	for _, route := range lb.Routes() {
		if !candidates.HasRegistry(route.RegistryID()) {
			excluded[route.Key()] = struct{}{}
		}
	}
	for _, reg := range rc.FallbackBackends {
		if !candidates.HasRegistry(reg.ID) {
			excluded[routingdomain.RouteForRegistry(reg).Key()] = struct{}{}
		}
	}
	return excluded
}

// The fallback chain picks registries, so a registry with any excluded route counts as tried.
func excludedRegistries(excluded map[routingdomain.RouteKey]struct{}) map[ids.RegistryID]struct{} {
	out := make(map[ids.RegistryID]struct{}, len(excluded))
	for key := range excluded {
		out[key.RegistryID] = struct{}{}
	}
	return out
}

func firstAvailableFallback(
	rc *appconsumer.RoutableConsumer,
	excluded map[routingdomain.RouteKey]struct{},
) *domain.Registry {
	if fb := rc.Consumer.Fallback; fb == nil || !fb.Enabled {
		return nil
	}
	skip := excludedRegistries(excluded)
	for _, bk := range rc.FallbackBackends {
		if _, blocked := skip[bk.ID]; !blocked {
			return bk
		}
	}
	return nil
}

func (f *forwarder) stampRoutingPolicy(
	dto *forwardRequestDTO,
	rc *appconsumer.RoutableConsumer,
	route routingdomain.Route,
) {
	bk := route.Registry
	dto.routeSource = routeSourceFor(dto.candidates, bk)
	allowed, defaultModel := candidatePolicy(dto.candidates, rc, bk)
	if route.Allowed != nil {
		allowed = route.Allowed
	}
	if route.Default != "" {
		defaultModel = route.Default
	}
	dto.request.AllowedModels = allowed
	if modelmatch.IsPattern(defaultModel) {
		defaultModel = ""
	}
	dto.request.DefaultModel = defaultModel
}

func candidatePolicy(
	candidates *routingdomain.CandidateSet,
	rc *appconsumer.RoutableConsumer,
	bk *domain.Registry,
) ([]string, string) {
	if candidate, ok := candidates.ForRegistry(bk.ID); ok {
		return candidate.Allowed, candidate.Default
	}
	policy, ok := rc.Consumer.ModelPolicies.For(bk.ID)
	if !ok {
		return nil, ""
	}
	return policy.Allowed, policy.Default
}

func routeSourceFor(candidates *routingdomain.CandidateSet, bk *domain.Registry) string {
	if candidate, ok := candidates.ForRegistry(bk.ID); ok && len(candidate.Sources) > 0 {
		return strings.Join(candidate.Sources, ",")
	}
	return "consumer"
}
