package loadbalancer

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/loadbalancer/strategies"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type BaseFactory struct{}

func NewBaseFactory() Factory {
	return &BaseFactory{}
}

func (f *BaseFactory) CreateStrategy(algorithm string, targets []types.UpstreamTarget) (Strategy, error) {
	switch algorithm {
	case "round-robin":
		return strategies.NewRoundRobin(targets), nil
	case "random":
		return strategies.NewRandom(targets), nil
	case "weighted-round-robin":
		return strategies.NewWeightedRoundRobin(targets), nil
	case "least-connections":
		return strategies.NewLeastConnections(targets), nil
	default:
		return nil, fmt.Errorf("unsupported load balancing algorithm: %s", algorithm)
	}
}
