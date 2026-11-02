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

package modules

import (
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/complexity"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	embeddingopenai "github.com/NeuralTrust/TrustGate/pkg/infra/embedding/openai"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer/strategies"
	"go.uber.org/dig"
)

type loadBalancerParams struct {
	dig.In
	EmbeddingRepo  embedding.Repository            `optional:"true"`
	ServiceLocator factory.EmbeddingServiceLocator `optional:"true"`
	Complexity     strategies.ComplexityScorer
	Logger         *slog.Logger
	Cache          cache.Client
}

func LoadBalancer(c *container.Container) error {
	if err := c.Provide(func() factory.EmbeddingServiceLocator {
		return factory.NewServiceLocator(factory.ProviderRegistry{
			embeddingopenai.ProviderName: embeddingopenai.NewCreator(),
		})
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config, logger *slog.Logger) strategies.ComplexityScorer {
		fc := cfg.FirewallComplexity
		return complexity.NewClient(fc.BaseURL, firewallTokenProvider(fc, logger), fc.Timeout, fc.ModelRevision)
	}); err != nil {
		return err
	}
	return c.Provide(func(p loadBalancerParams) loadbalancer.Factory {
		return loadbalancer.NewBaseFactory(p.EmbeddingRepo, p.ServiceLocator, p.Complexity, strategies.NewRedisSR1Store(p.Cache.RedisClient()), p.Logger)
	})
}

func firewallTokenProvider(fc config.FirewallComplexityConfig, logger *slog.Logger) complexity.TokenProvider {
	if !fc.JWTSet {
		return firewall.NewTokenProvider(fc.SecretKey)
	}
	if fc.SecretKey != "" {
		logger.Warn("FIREWALL_SECRET_KEY is ignored because FIREWALL_JWT is set")
	}
	if fc.JWTError != nil {
		logger.Warn("firewall client not loaded: smart-routing scoring will fail until FIREWALL_JWT is fixed",
			slog.String("error", fc.JWTError.Error()))
		return firewall.NewUnusableSource(fc.JWTError, logger)
	}
	logger.Info("firewall client loaded from FIREWALL_JWT",
		slog.String("base_url", fc.BaseURL),
		slog.String("base_url_source", fc.BaseURLSource),
		slog.String("client_id", fc.ClientID))
	return firewall.NewOAuthTokenSource(fc.BaseURL, fc.ClientID, fc.ClientSecret, logger)
}
