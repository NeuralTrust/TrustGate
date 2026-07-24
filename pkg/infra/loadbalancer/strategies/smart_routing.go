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
	"log/slog"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// ComplexityScorer scores the complexity of a user message in [0,1].
type ComplexityScorer interface {
	Score(ctx context.Context, input, conversationID, tenantID string) (float64, error)
	Configured() bool
}

// SmartRouting routes by the complexity of the incoming message: it asks the
// Firewall Complexity API for a score and maps that score to a target via the
// configured tiers. It fails open to round-robin whenever the scorer is not
// configured, the score is unavailable, or no candidate matches the score.
type SmartRouting struct {
	registries []*registry.Registry
	config     *registry.SmartRoutingConfig
	scorer     ComplexityScorer
	fallback   *RoundRobin
	logger     *slog.Logger
	warnOnce   sync.Once
}

func NewSmartRouting(
	registries []*registry.Registry,
	config *registry.SmartRoutingConfig,
	scorer ComplexityScorer,
	logger *slog.Logger,
) *SmartRouting {
	return &SmartRouting{
		registries: registries,
		config:     config,
		scorer:     scorer,
		fallback:   NewRoundRobin(registries),
		logger:     logger,
	}
}

func (s *SmartRouting) Name() string { return algorithm.SmartRouting }

func (s *SmartRouting) Next(
	ctx context.Context,
	req *infracontext.RequestContext,
	exclude map[ids.RegistryID]struct{},
) *registry.Registry {
	candidates := filterExcluded(s.registries, exclude)
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	if s.config == nil || s.scorer == nil || !s.scorer.Configured() || req == nil {
		return s.fallbackNext(ctx, req, exclude, "smart routing not configured")
	}
	input, err := extractPromptFromRequest(req.Body)
	if err != nil {
		return s.fallbackNext(ctx, req, exclude, "could not extract input from request")
	}
	score, err := s.scorer.Score(ctx, input, req.SessionID, req.GatewayID)
	if err != nil {
		return s.fallbackNext(ctx, req, exclude, "complexity score unavailable")
	}
	target := s.registryForScore(score, candidates)
	if target == nil {
		return s.fallbackNext(ctx, req, exclude, "no candidate matched complexity score")
	}
	if s.logger != nil {
		s.logger.Debug("smart routing selected registry",
			slog.String("registry_id", target.ID.String()),
			slog.Float64("score", score),
		)
	}
	return target
}

func (s *SmartRouting) registryForScore(score float64, candidates []*registry.Registry) *registry.Registry {
	id, ok := s.config.RegistryForScore(score)
	if !ok {
		return nil
	}
	for _, b := range candidates {
		if b.ID == id {
			return b
		}
	}
	return nil
}

func (s *SmartRouting) fallbackNext(
	ctx context.Context,
	req *infracontext.RequestContext,
	exclude map[ids.RegistryID]struct{},
	reason string,
) *registry.Registry {
	if s.logger != nil {
		s.warnOnce.Do(func() {
			s.logger.Warn("smart routing falling back to round-robin", slog.String("reason", reason))
		})
	}
	return s.fallback.Next(ctx, req, exclude)
}
