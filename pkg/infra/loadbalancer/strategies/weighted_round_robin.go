package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type WeightedRoundRobin struct {
	mu            sync.Mutex
	backends      []*backend.Backend
	currentIndex  int
	currentWeight int
	maxWeight     int
}

func NewWeightedRoundRobin(backends []*backend.Backend) *WeightedRoundRobin {
	maxWeight := 0
	for _, b := range backends {
		if b.Weight > maxWeight {
			maxWeight = b.Weight
		}
	}
	return &WeightedRoundRobin{
		backends:  backends,
		maxWeight: maxWeight,
	}
}

func (wrr *WeightedRoundRobin) Next(req *infracontext.RequestContext, exclude map[ids.BackendID]struct{}) *backend.Backend {
	wrr.mu.Lock()
	defer wrr.mu.Unlock()
	if len(wrr.backends) == 0 {
		return nil
	}

	maxIterations := len(wrr.backends)*(wrr.maxWeight+1) + 1
	for i := 0; i < maxIterations; i++ {
		wrr.currentIndex = (wrr.currentIndex + 1) % len(wrr.backends)
		if wrr.currentIndex == 0 {
			wrr.currentWeight = wrr.currentWeight - 1
			if wrr.currentWeight <= 0 {
				wrr.currentWeight = wrr.maxWeight
				if wrr.currentWeight == 0 {
					return nil
				}
			}
		}
		b := wrr.backends[wrr.currentIndex]
		if b.Weight >= wrr.currentWeight && !isExcluded(b.ID, exclude) {
			return b
		}
	}
	return nil
}

func (wrr *WeightedRoundRobin) Name() string {
	return algorithm.WeightedRoundRobin
}
