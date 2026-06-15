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
	weights       map[ids.RegistryID]int
	currentIndex  int
	currentWeight int
	maxWeight     int
}

func NewWeightedRoundRobin(registries []*registry.Registry, weights map[ids.RegistryID]int) *WeightedRoundRobin {
	wrr := &WeightedRoundRobin{
		registries: registries,
		weights:    weights,
	}
	for _, b := range registries {
		if wrr.effectiveWeight(b) > wrr.maxWeight {
			wrr.maxWeight = wrr.effectiveWeight(b)
		}
	}
	return wrr
}

func (wrr *WeightedRoundRobin) effectiveWeight(b *registry.Registry) int {
	if w, ok := wrr.weights[b.ID]; ok && w > 0 {
		return w
	}
	return 1
}

func (wrr *WeightedRoundRobin) Next(_ *infracontext.RequestContext, exclude map[ids.RegistryID]struct{}) *registry.Registry {
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
		if wrr.effectiveWeight(b) >= wrr.currentWeight && !isExcluded(b.ID, exclude) {
			return b
		}
	}
	return nil
}

func (wrr *WeightedRoundRobin) Name() string {
	return algorithm.WeightedRoundRobin
}
