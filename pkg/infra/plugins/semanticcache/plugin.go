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

// Package semanticcache implements a semantic response cache: on PreRequest it
// serves a cached response when a semantically similar request is found, and on
// PostResponse it stores successful upstream responses for future hits.
package semanticcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/semantic"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	embeddingfactory "github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// PluginName is the catalog name used in policy configuration.
const PluginName = "semantic_cache"

const defaultVectorDimension = 1536

// metadataCacheStatus records the PreRequest decision so PostResponse can skip
// re-storing a served cache hit.
const metadataCacheStatus = "semantic_cache_status"

const (
	cacheStatusHit  = "HIT"
	cacheStatusMiss = "MISS"
)

const geminiStreamAction = ":streamGenerateContent"

const (
	toolCallsFinishReason = "tool_calls"

	skipReasonTools     = "tools_present"
	skipReasonStreaming = "streaming"
)

var _ appplugins.Plugin = (*Plugin)(nil)

// Plugin caches responses by request embedding similarity, scoped per registry.
type Plugin struct {
	store     semantic.Store
	locator   embeddingfactory.EmbeddingServiceLocator
	registry  *adapter.Registry
	dimension int

	indexMu    sync.Mutex
	indexReady atomic.Bool
}

// Option customizes the plugin.
type Option func(*Plugin)

// WithDimension overrides the vector dimension used to create the index.
func WithDimension(dimension int) Option {
	return func(p *Plugin) {
		if dimension > 0 {
			p.dimension = dimension
		}
	}
}

// New builds a semantic cache plugin.
func New(
	store semantic.Store,
	locator embeddingfactory.EmbeddingServiceLocator,
	registry *adapter.Registry,
	opts ...Option,
) *Plugin {
	p := &Plugin{
		store:     store,
		locator:   locator,
		registry:  registry,
		dimension: defaultVectorDimension,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MutatesRequestBody() bool { return false }

func (p *Plugin) MutatesResponseBody() bool { return true }

func (p *Plugin) MutatesMetadata() bool { return true }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("semantic_cache: %w", err)
	}

	if p.bypassed(in.Request, cfg) {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Bypassed: true, Mode: cfg.mode(), Scope: cfg.scope()})
		return p.degraded(in), nil
	}

	partition, ok := partitionKey(cfg, in.Scope, in.Request)
	if !ok {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Degraded: true, DegradedReason: "no_partition", Scope: cfg.scope()})
		return p.degraded(in), nil
	}

	if err := p.ensureIndex(ctx); err != nil {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Degraded: true, DegradedReason: "index_unavailable"})
		return p.degraded(in), nil
	}
	creator, err := p.locator.GetService(cfg.provider())
	if err != nil {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Degraded: true, DegradedReason: "embedding_service_unavailable"})
		return p.degraded(in), nil
	}

	switch in.Stage {
	case policy.StagePreRequest:
		return p.preRequest(ctx, in, cfg, creator, partition)
	case policy.StagePostResponse:
		return p.postResponse(ctx, in, cfg, creator, partition)
	default:
		return passThrough(), nil
	}
}

func (p *Plugin) bypassed(req *infracontext.RequestContext, cfg *config) bool {
	if noCache(req) {
		return true
	}
	if req.HeaderValue(cfg.bypassHeader()) != "" {
		return true
	}
	if cfg.SkipIfStreaming && p.requestWantsStream(req) {
		return true
	}
	return false
}

func (p *Plugin) requestWantsStream(req *infracontext.RequestContext) bool {
	if req == nil {
		return false
	}
	if strings.Contains(req.Path, geminiStreamAction) {
		return true
	}
	if req.Query != nil && req.Query.Get("alt") == "sse" {
		return true
	}
	if req.Provider != "" && p.registry != nil {
		if canonical, err := p.registry.DecodeRequestFor(req.Body, adapter.Format(req.Provider)); err == nil && canonical != nil {
			return canonical.Stream
		}
	}
	if stream, explicit := adapter.RequestWantsStream(req.Body); explicit {
		return stream
	}
	return false
}

func (p *Plugin) requestHasTools(req *infracontext.RequestContext) bool {
	if req == nil || req.Provider == "" || p.registry == nil {
		return false
	}
	canonical, err := p.registry.DecodeRequestFor(req.Body, adapter.Format(req.Provider))
	if err != nil || canonical == nil {
		return false
	}
	return len(canonical.Tools) > 0
}

func (p *Plugin) responseHasToolCalls(provider string, resp *infracontext.ResponseContext) bool {
	if resp == nil || provider == "" || p.registry == nil {
		return false
	}
	canonical, err := p.registry.DecodeResponseFor(resp.Body, adapter.Format(provider))
	if err != nil || canonical == nil {
		return false
	}
	return len(canonical.ToolCalls) > 0 || canonical.FinishReason == toolCallsFinishReason
}

func (p *Plugin) degraded(in appplugins.ExecInput) *appplugins.Result {
	if in.Stage == policy.StagePreRequest {
		markStatus(in.Response, cacheStatusMiss)
		return missResult()
	}
	return passThrough()
}

func (p *Plugin) ensureIndex(ctx context.Context) error {
	if p.indexReady.Load() {
		return nil
	}
	p.indexMu.Lock()
	defer p.indexMu.Unlock()
	if p.indexReady.Load() {
		return nil
	}
	if err := p.store.EnsureIndex(ctx, p.dimension); err != nil {
		return err
	}
	p.indexReady.Store(true)
	return nil
}

func (p *Plugin) preRequest(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg *config,
	creator embedding.Creator,
	partition string,
) (*appplugins.Result, error) {
	if cfg.skipIfTools() && p.requestHasTools(in.Request) {
		markStatus(in.Response, cacheStatusMiss)
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, CacheHit: false, Scope: cfg.scope(), SkipReason: skipReasonTools})
		return missResult(), nil
	}

	text := p.extractUserInput(in.Request)
	if text == "" {
		markStatus(in.Response, cacheStatusMiss)
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, CacheHit: false, Scope: cfg.scope()})
		return missResult(), nil
	}

	emb, err := creator.Generate(ctx, text, cfg.model(), cfg.embeddingDomainConfig())
	if err != nil || emb == nil {
		markStatus(in.Response, cacheStatusMiss)
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Degraded: true, DegradedReason: "embedding_failed"})
		return missResult(), nil
	}

	candidates, err := p.store.Lookup(ctx, partition, emb, 1)
	if err != nil || len(candidates) == 0 || candidates[0].Similarity < cfg.SimilarityThreshold {
		markStatus(in.Response, cacheStatusMiss)
		miss := SemanticCacheData{
			Threshold:     cfg.SimilarityThreshold,
			CacheHit:      false,
			Scope:         cfg.scope(),
			EmbeddingSize: embeddingSize(emb),
			VectorDim:     p.dimension,
		}
		if err == nil && len(candidates) > 0 {
			miss.Similarity = candidates[0].Similarity
		}
		setCacheExtras(in.Event, miss)
		return missResult(), nil
	}

	best := candidates[0]
	if in.Mode == policy.ModeObserve {
		markStatus(in.Response, cacheStatusMiss)
		setCacheExtras(in.Event, SemanticCacheData{
			Threshold:     cfg.SimilarityThreshold,
			CacheHit:      true,
			Stored:        false,
			Similarity:    best.Similarity,
			EmbeddingSize: embeddingSize(emb),
			VectorDim:     p.dimension,
		})
		appplugins.SetDecision(in.Event, in.Mode)
		return missResult(), nil
	}

	markStatus(in.Response, cacheStatusHit)
	setCacheExtras(in.Event, SemanticCacheData{
		Threshold:     cfg.SimilarityThreshold,
		CacheHit:      true,
		Scope:         cfg.scope(),
		Similarity:    best.Similarity,
		EmbeddingSize: embeddingSize(emb),
		VectorDim:     p.dimension,
	})
	return &appplugins.Result{
		StatusCode:   http.StatusOK,
		Body:         []byte(best.Response),
		StopUpstream: true,
		Headers: map[string][]string{
			"X-Cache":            {cacheStatusHit},
			"X-Cache-Status":     {cacheStatusHit},
			"X-Cache-Similarity": {fmt.Sprintf("%.4f", best.Similarity)},
		},
	}, nil
}

func (p *Plugin) postResponse(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg *config,
	creator embedding.Creator,
	partition string,
) (*appplugins.Result, error) {
	resp := in.Response
	if resp == nil || len(resp.Body) == 0 {
		return passThrough(), nil
	}
	if !cfg.cacheableStatus(resp.StatusCode) {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Stored: false, Scope: cfg.scope(), SkipReason: "status"})
		return passThrough(), nil
	}
	if in.Mode == policy.ModeObserve {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Stored: false, Scope: cfg.scope()})
		return passThrough(), nil
	}
	if statusOf(resp) == cacheStatusHit {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, CacheHit: true, Stored: false, Scope: cfg.scope()})
		return passThrough(), nil
	}
	if cfg.SkipIfStreaming && resp.Streaming {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Stored: false, Scope: cfg.scope(), SkipReason: skipReasonStreaming})
		return passThrough(), nil
	}
	if cfg.skipIfTools() && (p.requestHasTools(in.Request) || p.responseHasToolCalls(providerOf(in.Request), resp)) {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Stored: false, Scope: cfg.scope(), SkipReason: skipReasonTools})
		return passThrough(), nil
	}

	text := p.extractUserInput(in.Request)
	if text == "" {
		return passThrough(), nil
	}

	emb, err := creator.Generate(ctx, text, cfg.model(), cfg.embeddingDomainConfig())
	if err != nil || emb == nil {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Degraded: true, DegradedReason: "embedding_failed"})
		return passThrough(), nil
	}

	if err := p.store.Store(ctx, semantic.Entry{
		RuleID:    partition,
		Embedding: emb,
		Response:  string(resp.Body),
		TTL:       cfg.resolvedTTL(),
	}); err != nil {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Degraded: true, DegradedReason: "store_failed", EmbeddingSize: embeddingSize(emb), VectorDim: p.dimension})
		return passThrough(), nil
	}
	setCacheExtras(in.Event, SemanticCacheData{
		Threshold:     cfg.SimilarityThreshold,
		Stored:        true,
		Scope:         cfg.scope(),
		EmbeddingSize: embeddingSize(emb),
		VectorDim:     p.dimension,
	})
	return passThrough(), nil
}

func embeddingSize(emb *embedding.Embedding) int {
	if emb == nil {
		return 0
	}
	return len(emb.Value)
}

func setCacheExtras(event *metrics.EventContext, data SemanticCacheData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

func (p *Plugin) extractUserInput(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	if req.Provider != "" && p.registry != nil {
		canonical, err := p.registry.DecodeRequestFor(req.Body, adapter.Format(req.Provider))
		if err == nil && canonical != nil {
			for i := len(canonical.Messages) - 1; i >= 0; i-- {
				if canonical.Messages[i].Role == "user" && canonical.Messages[i].Content != "" {
					return canonical.Messages[i].Content
				}
			}
			return ""
		}
	}
	return adapter.ExtractUserInputGeneric(req.Body)
}

func partitionKey(cfg *config, scope appplugins.RuntimeScope, req *infracontext.RequestContext) (string, bool) {
	registry := registryNamespace(req)
	switch cfg.scope() {
	case scopeGlobal:
		if scope.GatewayID == "" {
			return "", false
		}
		return registry + "|g:" + scope.GatewayID, true
	default:
		if scope.ConsumerID == "" {
			return "", false
		}
		return registry + "|c:" + scope.ConsumerID, true
	}
}

func exactKey(partition, text string) string {
	sum := sha256.Sum256([]byte(partition + "\x00" + normalize(text)))
	return hex.EncodeToString(sum[:])
}

func normalize(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

func registryNamespace(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	if req.RegistryID != "" {
		return req.RegistryID
	}
	return req.GatewayID
}

func providerOf(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	return req.Provider
}

func noCache(req *infracontext.RequestContext) bool {
	if req == nil {
		return false
	}
	values, ok := req.Headers["Cache-Control"]
	return ok && len(values) > 0 && values[0] == "no-cache"
}

func markStatus(resp *infracontext.ResponseContext, status string) {
	if resp == nil {
		return
	}
	if resp.Metadata == nil {
		resp.Metadata = make(map[string]interface{})
	}
	resp.Metadata[metadataCacheStatus] = status
}

func statusOf(resp *infracontext.ResponseContext) string {
	if resp == nil || resp.Metadata == nil {
		return ""
	}
	if s, ok := resp.Metadata[metadataCacheStatus].(string); ok {
		return s
	}
	return ""
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}

func missResult() *appplugins.Result {
	return &appplugins.Result{
		StatusCode: http.StatusOK,
		Headers: map[string][]string{
			"X-Cache":        {cacheStatusMiss},
			"X-Cache-Status": {cacheStatusMiss},
		},
	}
}
