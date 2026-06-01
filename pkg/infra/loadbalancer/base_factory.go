package loadbalancer

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/strategies"
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
		return strategies.NewRoundRobin(input.Backends), nil
	case algorithm.Random:
		return strategies.NewRandom(input.Backends), nil
	case algorithm.WeightedRoundRobin:
		return strategies.NewWeightedRoundRobin(input.Backends), nil
	case algorithm.LeastConnections:
		return strategies.NewLeastConnections(input.Backends), nil
	case algorithm.Semantic:
		return strategies.NewSemantic(input.EmbeddingConfig, input.Backends, f.embeddingRepo, f.serviceLocator), nil
	default:
		return nil, fmt.Errorf("unsupported load balancing algorithm: %s", input.Algorithm)
	}
}
