package loadbalancer

import (
	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
	"github.com/google/uuid"
)

const (
	AlgorithmRoundRobin         = algorithm.RoundRobin
	AlgorithmRandom             = algorithm.Random
	AlgorithmWeightedRoundRobin = algorithm.WeightedRoundRobin
	AlgorithmLeastConnections   = algorithm.LeastConnections
	AlgorithmSemantic           = algorithm.Semantic
)

type Strategy interface {
	Next(req *infracontext.RequestContext, exclude map[uuid.UUID]struct{}) *backend.Backend
	Name() string
}

type StrategyInput struct {
	Algorithm       string
	Backends        []*backend.Backend
	EmbeddingConfig *embedding.Config
}

type Factory interface {
	CreateStrategy(input StrategyInput) (Strategy, error)
}

func Algorithms() []string { return algorithm.Names() }

func IsValidAlgorithm(name string) bool { return algorithm.IsValid(name) }
