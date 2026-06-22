// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package strategies

import (
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer/algorithm"
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
