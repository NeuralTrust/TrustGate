package strategies

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type Semantic struct {
	mu              sync.Mutex
	embeddingConfig *types.EmbeddingConfig
	targets         []types.UpstreamTarget
	client          *http.Client
	embeddingRepo   embedding.Repository
	serviceLocator  *factory.EmbeddingServiceLocator
}

func NewSemantic(
	embeddingConfig *types.EmbeddingConfig,
	targets []types.UpstreamTarget,
	embeddingRepo embedding.Repository,
	serviceLocator *factory.EmbeddingServiceLocator,
) *Semantic {
	return &Semantic{
		embeddingConfig: embeddingConfig,
		targets:         targets,
		client:          &http.Client{},
		embeddingRepo:   embeddingRepo,
		serviceLocator:  serviceLocator,
	}
}

func (s *Semantic) Next(req *types.RequestContext) *types.UpstreamTarget {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.targets) == 0 {
		return nil
	}

	if len(s.targets) == 1 {
		return &s.targets[0]
	}

	prompt, err := s.extractPromptFromRequest(req.Body)
	if err != nil {
		return &s.targets[0]
	}

	promptEmbedding, err := s.generateEmbedding(prompt)
	if err != nil {
		return &s.targets[0]
	}

	bestTarget, err := s.findSimilarTarget(req.Context, promptEmbedding)
	if err != nil || bestTarget == nil {
		return &s.targets[0]
	}

	return bestTarget
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

func (s *Semantic) generateEmbedding(text string) ([]float64, error) {
	embeddingService, err := s.serviceLocator.GetService(factory.OpenAIProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to get embedding service: %w", err)
	}
	if s.embeddingConfig == nil {
		return nil, fmt.Errorf("embedding config not found")
	}
	embeddingConfig := &embedding.Config{
		Provider: s.embeddingConfig.Provider,
		Model:    s.embeddingConfig.Model,
		Credentials: domain.CredentialsJSON{
			HeaderName:  s.embeddingConfig.Credentials.HeaderName,
			HeaderValue: s.embeddingConfig.Credentials.HeaderValue,
		},
	}
	emb, err := embeddingService.Generate(context.Background(), text, embeddingConfig.Model, embeddingConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate embedding: %w", err)
	}

	return emb.Value, nil
}

func (s *Semantic) findSimilarTarget(ctx context.Context, promptEmbedding []float64) (*types.UpstreamTarget, error) {
	var bestTarget *types.UpstreamTarget
	var bestSimilarity float64 = -1

	for i, target := range s.targets {
		if target.Description == "" {
			continue
		}
		targetEmbedding, err := s.embeddingRepo.GetByTargetID(ctx, target.ID)
		if err != nil {
			continue
		}
		similarity := s.cosineSimilarity(promptEmbedding, targetEmbedding.Value)
		if similarity > bestSimilarity {
			bestSimilarity = similarity
			bestTarget = &s.targets[i]
		}
	}
	if bestTarget == nil {
		return &s.targets[0], nil
	}
	return bestTarget, nil
}

func (s *Semantic) cosineSimilarity(a, b []float64) float64 {
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
