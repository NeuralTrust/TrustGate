package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type WeightedRoundRobin struct {
	mu            sync.Mutex
	registries    []*registry.Registry
	currentIndex  int
	currentWeight int
	maxWeight     int
}

func NewWeightedRoundRobin(registries []*registry.Registry) *WeightedRoundRobin {
	maxWeight := 0
	for _, b := range registries {
		if effectiveWeight(b) > maxWeight {
			maxWeight = effectiveWeight(b)
		}
	}
	return &WeightedRoundRobin{
		registries: registries,
		maxWeight:  maxWeight,
	}
}

func effectiveWeight(b *registry.Registry) int {
	if b.Weight <= 0 {
		return 1
	}
	return b.Weight
}

func (wrr *WeightedRoundRobin) Next(req *infracontext.RequestContext, exclude map[ids.RegistryID]struct{}) *registry.Registry {
	wrr.mu.Lock()
	defer wrr.mu.Unlock()
	if len(wrr.registries) == 0 {
		return nil
	}

	maxIterations := len(wrr.registries)*(wrr.maxWeight+1) + 1
	for i := 0; i < maxIterations; i++ {
		wrr.currentIndex = (wrr.currentIndex + 1) % len(wrr.registries)
		if wrr.currentIndex == 0 {
			wrr.currentWeight = wrr.currentWeight - 1
			if wrr.currentWeight <= 0 {
				wrr.currentWeight = wrr.maxWeight
				if wrr.currentWeight == 0 {
					return nil
				}
			}
		}
		b := wrr.registries[wrr.currentIndex]
		if effectiveWeight(b) >= wrr.currentWeight && !isExcluded(b.ID, exclude) {
			return b
		}
	}
	return nil
}

func (wrr *WeightedRoundRobin) Name() string {
	return algorithm.WeightedRoundRobin
}
