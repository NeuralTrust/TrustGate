package strategies

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
	"github.com/google/uuid"
)

type Semantic struct {
	mu              sync.RWMutex
	backends        []*backend.Backend
	embeddingRepo   embedding.Repository
	serviceLocator  factory.EmbeddingServiceLocator
	embeddingConfig *embedding.Config
}

func NewSemantic(
	embeddingCfg *embedding.Config,
	backends []*backend.Backend,
	embeddingRepo embedding.Repository,
	serviceLocator factory.EmbeddingServiceLocator,
) *Semantic {
	return &Semantic{
		backends:        backends,
		embeddingRepo:   embeddingRepo,
		serviceLocator:  serviceLocator,
		embeddingConfig: embeddingCfg,
	}
}

func (s *Semantic) Next(req *infracontext.RequestContext, exclude map[uuid.UUID]struct{}) *backend.Backend {
	s.mu.RLock()
	defer s.mu.RUnlock()

	candidates := filterExcluded(s.backends, exclude)
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	if s.embeddingConfig == nil || s.serviceLocator == nil || s.embeddingRepo == nil || req == nil {
		return candidates[0]
	}

	prompt, err := extractPromptFromRequest(req.Body)
	if err != nil {
		return candidates[0]
	}
	promptEmbedding, err := s.generateEmbedding(req.Context, prompt)
	if err != nil {
		return candidates[0]
	}
	return s.findBestBackend(req.Context, promptEmbedding, candidates)
}

func (s *Semantic) Name() string {
	return algorithm.Semantic
}

func extractPromptFromRequest(body []byte) (string, error) {
	if len(body) == 0 {
		return "", fmt.Errorf("empty request body")
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	if prompt, ok := data["prompt"].(string); ok {
		return prompt, nil
	}
	if messages, ok := data["messages"].([]interface{}); ok && len(messages) > 0 {
		lastMsg := messages[len(messages)-1]
		if msgMap, ok := lastMsg.(map[string]interface{}); ok {
			if content, ok := msgMap["content"].(string); ok {
				return content, nil
			}
		}
	}
	return "", fmt.Errorf("could not extract prompt from request")
}

func (s *Semantic) generateEmbedding(ctx context.Context, text string) ([]float64, error) {
	provider := s.embeddingConfig.Provider
	if provider == "" {
		provider = factory.OpenAIProvider
	}
	svc, err := s.serviceLocator.GetService(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get embedding service: %w", err)
	}
	emb, err := svc.Generate(ctx, text, s.embeddingConfig.Model, s.embeddingConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate embedding: %w", err)
	}
	return emb.Value, nil
}

func (s *Semantic) findBestBackend(
	ctx context.Context,
	promptEmbedding []float64,
	candidates []*backend.Backend,
) *backend.Backend {
	var bestBackend *backend.Backend
	bestSimilarity := -1.0
	for _, b := range candidates {
		if b.Description == "" {
			continue
		}
		backendEmbedding, err := s.embeddingRepo.GetByTargetID(ctx, b.ID.String())
		if err != nil {
			continue
		}
		similarity := cosineSimilarity(promptEmbedding, backendEmbedding.Value)
		if similarity > bestSimilarity {
			bestSimilarity = similarity
			bestBackend = b
		}
	}
	if bestBackend == nil {
		return candidates[0]
	}
	return bestBackend
}

func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dotProduct, magnitudeA, magnitudeB float64
	for i := range a {
		dotProduct += a[i] * b[i]
		magnitudeA += a[i] * a[i]
		magnitudeB += b[i] * b[i]
	}
	magnitudeA = math.Sqrt(magnitudeA)
	magnitudeB = math.Sqrt(magnitudeB)
	if magnitudeA == 0 || magnitudeB == 0 {
		return 0
	}
	return dotProduct / (magnitudeA * magnitudeB)
}
