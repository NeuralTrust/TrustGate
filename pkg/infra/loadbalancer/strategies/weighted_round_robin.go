package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type WeightedRoundRobin struct {
	mu            sync.Mutex
	targets       []backend.Target
	currentIndex  int
	currentWeight int
	maxWeight     int
}

func NewWeightedRoundRobin(targets []backend.Target) *WeightedRoundRobin {
	maxWeight := 0
	for _, target := range targets {
		if target.Weight > maxWeight {
			maxWeight = target.Weight
		}
	}
	return &WeightedRoundRobin{
		targets:   targets,
		maxWeight: maxWeight,
	}
}

func (wrr *WeightedRoundRobin) Next(req *infracontext.RequestContext) *backend.Target {
	wrr.mu.Lock()
	defer wrr.mu.Unlock()
	if len(wrr.targets) == 0 {
		return nil
	}
	for {
		wrr.currentIndex = (wrr.currentIndex + 1) % len(wrr.targets)
		if wrr.currentIndex == 0 {
			wrr.currentWeight = wrr.currentWeight - 1
			if wrr.currentWeight <= 0 {
				wrr.currentWeight = wrr.maxWeight
				if wrr.currentWeight == 0 {
					return nil
				}
			}
		}
		if wrr.targets[wrr.currentIndex].Weight >= wrr.currentWeight {
			return &wrr.targets[wrr.currentIndex]
		}
	}
}

func (wrr *WeightedRoundRobin) Name() string {
	return algorithm.WeightedRoundRobin
}
