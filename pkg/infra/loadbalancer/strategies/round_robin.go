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

type RoundRobin struct {
	mu      sync.Mutex
	routes  []routingdomain.Route
	current int
}

func NewRoundRobin(routes []routingdomain.Route) *RoundRobin {
	return &RoundRobin{routes: routes}
}

func (rr *RoundRobin) Next(
	_ context.Context,
	_ *infracontext.RequestContext,
	exclude map[routingdomain.RouteKey]struct{},
) *routingdomain.Route {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	n := len(rr.routes)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		route := rr.routes[rr.current]
		rr.current = (rr.current + 1) % n
		if !isExcluded(route.Key(), exclude) {
			return pick(route)
		}
	}
	return nil
}

func (rr *RoundRobin) Name() string {
	return algorithm.RoundRobin
}
