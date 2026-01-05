package loadbalancer

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer/strategies"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type FactoryInitializer func(
	embeddingRepo embedding.Repository,
	serviceLocator factory.EmbeddingServiceLocator,
) Factory

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

func (f *BaseFactory) CreateStrategy(upstream *types.UpstreamDTO) (Strategy, error) {
	switch upstream.Algorithm {
	case "round-robin":
		return strategies.NewRoundRobin(upstream.Targets), nil
	case "random":
		return strategies.NewRandom(upstream.Targets), nil
	case "weighted-round-robin":
		return strategies.NewWeightedRoundRobin(upstream.Targets), nil
	case "least-connections":
		return strategies.NewLeastConnections(upstream.Targets), nil
	case "semantic":
		return strategies.NewSemantic(upstream.EmbeddingConfig, upstream.Targets, f.embeddingRepo, f.serviceLocator), nil
	default:
		return nil, fmt.Errorf("unsupported load balancing algorithm: %s", upstream.Algorithm)
	}
}
