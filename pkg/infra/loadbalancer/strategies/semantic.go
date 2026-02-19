package strategies

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type Semantic struct {
	mu              sync.RWMutex
	targets         []types.UpstreamTargetDTO
	embeddingRepo   embedding.Repository
	serviceLocator  factory.EmbeddingServiceLocator
	embeddingConfig *embedding.Config
}

func NewSemantic(
	embeddingCfg *types.EmbeddingConfigDTO,
	targets []types.UpstreamTargetDTO,
	embeddingRepo embedding.Repository,
	serviceLocator factory.EmbeddingServiceLocator,
) *Semantic {
	s := &Semantic{
		targets:        targets,
		embeddingRepo:  embeddingRepo,
		serviceLocator: serviceLocator,
	}
	if embeddingCfg != nil {
		s.embeddingConfig = s.buildEmbeddingConfig(embeddingCfg)
	}
	return s
}

func (s *Semantic) buildEmbeddingConfig(cfg *types.EmbeddingConfigDTO) *embedding.Config {
	creds := domain.CredentialsJSON{
		HeaderName:  cfg.Credentials.HeaderName,
		HeaderValue: cfg.Credentials.HeaderValue,
	}
	if cfg.Credentials.ApiKey != "" {
		creds.ApiKey = cfg.Credentials.ApiKey
	} else if creds.HeaderValue != "" {
		creds.ApiKey = creds.HeaderValue
	}
	return &embedding.Config{
		Provider:    cfg.Provider,
		Model:       cfg.Model,
		Credentials: creds,
	}
}

func (s *Semantic) Next(req *types.RequestContext) *types.UpstreamTargetDTO {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.targets) == 0 {
		return nil
	}

	if len(s.targets) == 1 {
		return &s.targets[0]
	}

	if s.embeddingConfig == nil {
		return &s.targets[0]
	}

	prompt, err := s.extractPromptFromRequest(req.Body)
	if err != nil {
		return &s.targets[0]
	}

	promptEmbedding, err := s.generateEmbedding(req.Context, prompt)
	if err != nil {
		return &s.targets[0]
	}

	return s.findBestTarget(req.Context, promptEmbedding)
}

func (s *Semantic) Name() string {
	return common.SemanticStrategyName
}

func (s *Semantic) extractPromptFromRequest(body []byte) (string, error) {
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
	embeddingService, err := s.serviceLocator.GetService(factory.OpenAIProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to get embedding service: %w", err)
	}
	emb, err := embeddingService.Generate(ctx, text, s.embeddingConfig.Model, s.embeddingConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate embedding: %w", err)
	}
	return emb.Value, nil
}

func (s *Semantic) findBestTarget(ctx context.Context, promptEmbedding []float64) *types.UpstreamTargetDTO {
	var bestTarget *types.UpstreamTargetDTO
	var bestSimilarity float64 = -1

	for i, target := range s.targets {
		if target.Description == "" {
			continue
		}
		targetEmbedding, err := s.embeddingRepo.GetByTargetID(ctx, target.ID)
		if err != nil {
			continue
		}
		similarity := cosineSimilarity(promptEmbedding, targetEmbedding.Value)
		if similarity > bestSimilarity {
			bestSimilarity = similarity
			bestTarget = &s.targets[i]
		}
	}
	if bestTarget == nil {
		return &s.targets[0]
	}
	return bestTarget
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
