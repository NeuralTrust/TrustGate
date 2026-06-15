package loadbalancer

import (
	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

const (
	AlgorithmRoundRobin         = algorithm.RoundRobin
	AlgorithmRandom             = algorithm.Random
	AlgorithmWeightedRoundRobin = algorithm.WeightedRoundRobin
	AlgorithmLeastConnections   = algorithm.LeastConnections
	AlgorithmSemantic           = algorithm.Semantic
)

type Strategy interface {
	Next(req *infracontext.RequestContext, exclude map[ids.RegistryID]struct{}) *registry.Registry
	Name() string
}

type StrategyInput struct {
	Algorithm       string
	Registries      []*registry.Registry
	Weights         map[ids.RegistryID]int
	EmbeddingConfig *embedding.Config
}

type Factory interface {
	CreateStrategy(input StrategyInput) (Strategy, error)
}

func Algorithms() []string { return algorithm.Names() }

func IsValidAlgorithm(name string) bool { return algorithm.IsValid(name) }
