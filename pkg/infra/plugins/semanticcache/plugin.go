// Package semanticcache implements a semantic response cache: on PreRequest it
// serves a cached response when a semantically similar request is found, and on
// PostResponse it stores successful upstream responses for future hits.
package semanticcache

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/semantic"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	embeddingfactory "github.com/NeuralTrust/AgentGateway/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
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

var _ appplugins.Plugin = (*Plugin)(nil)

// Plugin caches responses by request embedding similarity, scoped per backend.
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

func (p *Plugin) Stages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if noCache(in.Request) {
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}

	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("semantic_cache: %w", err)
	}

	// Degraded pass-through: never fail the request on cache infrastructure
	// problems.
	if err := p.ensureIndex(ctx); err != nil {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Degraded: true, DegradedReason: "index_unavailable"})
		return passThrough(), nil
	}
	creator, err := p.locator.GetService(cfg.Embedding.Provider)
	if err != nil {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Degraded: true, DegradedReason: "embedding_service_unavailable"})
		return passThrough(), nil
	}

	switch in.Stage {
	case policy.StagePreRequest:
		return p.preRequest(ctx, in, cfg, creator)
	case policy.StagePostResponse:
		return p.postResponse(ctx, in, cfg, creator)
	default:
		return passThrough(), nil
	}
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
) (*appplugins.Result, error) {
	text := p.extractUserInput(in.Request)
	if text == "" {
		markStatus(in.Response, cacheStatusMiss)
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, CacheHit: false})
		return passThrough(), nil
	}

	emb, err := creator.Generate(ctx, text, cfg.Embedding.Model, cfg.embeddingDomainConfig())
	if err != nil || emb == nil {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Degraded: true, DegradedReason: "embedding_failed"})
		return passThrough(), nil
	}

	candidates, err := p.store.Lookup(ctx, scopeID(in.Request), emb, 1)
	if err != nil || len(candidates) == 0 || candidates[0].Similarity < cfg.SimilarityThreshold {
		markStatus(in.Response, cacheStatusMiss)
		miss := SemanticCacheData{
			Threshold:     cfg.SimilarityThreshold,
			CacheHit:      false,
			EmbeddingSize: embeddingSize(emb),
			VectorDim:     p.dimension,
		}
		if err == nil && len(candidates) > 0 {
			miss.Similarity = candidates[0].Similarity
		}
		setCacheExtras(in.Event, miss)
		return passThrough(), nil
	}

	best := candidates[0]
	markStatus(in.Response, cacheStatusHit)
	setCacheExtras(in.Event, SemanticCacheData{
		Threshold:     cfg.SimilarityThreshold,
		CacheHit:      true,
		Similarity:    best.Similarity,
		EmbeddingSize: embeddingSize(emb),
		VectorDim:     p.dimension,
	})
	return &appplugins.Result{
		StatusCode:   http.StatusOK,
		Body:         []byte(best.Response),
		StopUpstream: true,
		Headers: map[string][]string{
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
) (*appplugins.Result, error) {
	resp := in.Response
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 || len(resp.Body) == 0 {
		return passThrough(), nil
	}
	if statusOf(resp) == cacheStatusHit {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, CacheHit: true, Stored: false})
		return passThrough(), nil
	}

	text := p.extractUserInput(in.Request)
	if text == "" {
		return passThrough(), nil
	}

	emb, err := creator.Generate(ctx, text, cfg.Embedding.Model, cfg.embeddingDomainConfig())
	if err != nil || emb == nil {
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Degraded: true, DegradedReason: "embedding_failed"})
		return passThrough(), nil
	}

	if err := p.store.Store(ctx, semantic.Entry{
		RuleID:    scopeID(in.Request),
		Embedding: emb,
		Response:  string(resp.Body),
		TTL:       cfg.parsedTTL(),
	}); err != nil {
		// Storing is best-effort; never fail the response.
		setCacheExtras(in.Event, SemanticCacheData{Threshold: cfg.SimilarityThreshold, Degraded: true, DegradedReason: "store_failed", EmbeddingSize: embeddingSize(emb), VectorDim: p.dimension})
		return passThrough(), nil
	}
	setCacheExtras(in.Event, SemanticCacheData{
		Threshold:     cfg.SimilarityThreshold,
		Stored:        true,
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

// extractUserInput returns the last user message for embedding. It uses the
// provider-aware adapter when a provider is known, falling back to a generic
// JSON extraction.
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

// scopeID isolates cache entries. Backend id is preferred so identical requests
// to different upstreams do not collide; gateway id is the fallback.
func scopeID(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	if req.BackendID != "" {
		return req.BackendID
	}
	return req.GatewayID
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
