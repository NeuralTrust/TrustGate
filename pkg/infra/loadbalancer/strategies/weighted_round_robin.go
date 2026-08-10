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
	"context"
	"sync"

	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

type WeightedRoundRobin struct {
	mu            sync.Mutex
	routes        []routingdomain.Route
	currentIndex  int
	currentWeight int
	maxWeight     int
}

func NewWeightedRoundRobin(routes []routingdomain.Route) *WeightedRoundRobin {
	wrr := &WeightedRoundRobin{routes: routes}
	for _, route := range routes {
		if w := route.EffectiveWeight(); w > wrr.maxWeight {
			wrr.maxWeight = w
		}
	}
	return wrr
}

func (wrr *WeightedRoundRobin) Next(
	_ context.Context,
	_ *infracontext.RequestContext,
	exclude map[routingdomain.RouteKey]struct{},
) *routingdomain.Route {
	wrr.mu.Lock()
	defer wrr.mu.Unlock()
	if len(wrr.routes) == 0 {
		return nil
	}

	maxIterations := len(wrr.routes)*(wrr.maxWeight+1) + 1
	for i := 0; i < maxIterations; i++ {
		wrr.currentIndex = (wrr.currentIndex + 1) % len(wrr.routes)
		if wrr.currentIndex == 0 {
			wrr.currentWeight = wrr.currentWeight - 1
			if wrr.currentWeight <= 0 {
				wrr.currentWeight = wrr.maxWeight
				if wrr.currentWeight == 0 {
					return nil
				}
			}
		}
		route := wrr.routes[wrr.currentIndex]
		if route.EffectiveWeight() >= wrr.currentWeight && !isExcluded(route.Key(), exclude) {
			return pick(route)
		}
	}
	return nil
}

func (wrr *WeightedRoundRobin) Name() string {
	return algorithm.WeightedRoundRobin
}
