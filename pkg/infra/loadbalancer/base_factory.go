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

package loadbalancer

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer/strategies"
)

var _ Factory = (*BaseFactory)(nil)

type BaseFactory struct {
	embeddingRepo  embedding.Repository
	serviceLocator factory.EmbeddingServiceLocator
}

func NewBaseFactory(
	embeddingRepo embedding.Repository,
	serviceLocator factory.EmbeddingServiceLocator,
) Factory {
	return &BaseFactory{
		embeddingRepo:  embeddingRepo,
		serviceLocator: serviceLocator,
	}
}

func (f *BaseFactory) CreateStrategy(input StrategyInput) (Strategy, error) {
	switch input.Algorithm {
	case algorithm.RoundRobin:
		return strategies.NewRoundRobin(input.Registries), nil
	case algorithm.Random:
		return strategies.NewRandom(input.Registries), nil
	case algorithm.WeightedRoundRobin:
		return strategies.NewWeightedRoundRobin(input.Registries, input.Weights), nil
	case algorithm.LeastConnections:
		return strategies.NewLeastConnections(input.Registries), nil
	case algorithm.Semantic:
		return strategies.NewSemantic(input.EmbeddingConfig, input.Registries, f.embeddingRepo, f.serviceLocator), nil
	default:
		return nil, fmt.Errorf("unsupported load balancing algorithm: %s", input.Algorithm)
	}
}
