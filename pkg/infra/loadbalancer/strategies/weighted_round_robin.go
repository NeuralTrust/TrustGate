package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
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

func (wrr *WeightedRoundRobin) Next(req *infracontext.RequestContext) *backend.Backend {
	wrr.mu.Lock()
	defer wrr.mu.Unlock()
	if len(wrr.backends) == 0 {
		return nil
	}
	for {
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
		if wrr.backends[wrr.currentIndex].Weight >= wrr.currentWeight {
			return wrr.backends[wrr.currentIndex]
		}
	}
}

func (wrr *WeightedRoundRobin) Name() string {
	return algorithm.WeightedRoundRobin
}
