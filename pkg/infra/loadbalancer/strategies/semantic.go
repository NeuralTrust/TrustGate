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

package strategies

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
)

type backendVector struct {
	value     []float64
	magnitude float64
}

type Semantic struct {
	mu              sync.RWMutex
	registries      []*registry.Registry
	embeddingRepo   embedding.Repository
	serviceLocator  factory.EmbeddingServiceLocator
	embeddingConfig *embedding.Config

	vecMu    sync.Mutex
	vecCache map[string]*backendVector
}

func NewSemantic(
	embeddingCfg *embedding.Config,
	registries []*registry.Registry,
	embeddingRepo embedding.Repository,
	serviceLocator factory.EmbeddingServiceLocator,
) *Semantic {
	return &Semantic{
		registries:      registries,
		embeddingRepo:   embeddingRepo,
		serviceLocator:  serviceLocator,
		embeddingConfig: embeddingCfg,
		vecCache:        make(map[string]*backendVector),
	}
}

func (s *Semantic) Next(ctx context.Context, req *infracontext.RequestContext, exclude map[ids.RegistryID]struct{}) *registry.Registry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	candidates := filterExcluded(s.registries, exclude)
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
	promptEmbedding, err := s.generateEmbedding(ctx, prompt)
	if err != nil {
		return candidates[0]
	}
	return s.findBestRegistry(ctx, promptEmbedding, candidates)
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

func (s *Semantic) findBestRegistry(
	ctx context.Context,
	promptEmbedding []float64,
	candidates []*registry.Registry,
) *registry.Registry {
	promptMagnitude := magnitude(promptEmbedding)
	var bestBackend *registry.Registry
	bestSimilarity := -1.0
	for _, b := range candidates {
		if b.Description == "" {
			continue
		}
		bv := s.backendVector(ctx, b.ID.String())
		if bv == nil {
			continue
		}
		similarity := cosineSimilarity(promptEmbedding, promptMagnitude, bv.value, bv.magnitude)
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

// backendVector returns the target's embedding and its precomputed magnitude,
// fetching from the repository only once per target: backend embeddings are
// immutable for the lifetime of a strategy instance, so caching avoids a
// repository round-trip and a magnitude recomputation on every request.
func (s *Semantic) backendVector(ctx context.Context, targetID string) *backendVector {
	s.vecMu.Lock()
	if bv, ok := s.vecCache[targetID]; ok {
		s.vecMu.Unlock()
		return bv
	}
	s.vecMu.Unlock()

	emb, err := s.embeddingRepo.GetByTargetID(ctx, targetID)
	if err != nil {
		return nil
	}
	bv := &backendVector{value: emb.Value, magnitude: magnitude(emb.Value)}

	s.vecMu.Lock()
	s.vecCache[targetID] = bv
	s.vecMu.Unlock()
	return bv
}

func magnitude(v []float64) float64 {
	var sum float64
	for _, x := range v {
		sum += x * x
	}
	return math.Sqrt(sum)
}

func cosineSimilarity(a []float64, magnitudeA float64, b []float64, magnitudeB float64) float64 {
	if len(a) != len(b) || magnitudeA == 0 || magnitudeB == 0 {
		return 0
	}
	var dotProduct float64
	for i := range a {
		dotProduct += a[i] * b[i]
	}
	return dotProduct / (magnitudeA * magnitudeB)
}
