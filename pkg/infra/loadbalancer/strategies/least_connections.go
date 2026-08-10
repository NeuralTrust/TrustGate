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
	"slices"
	"sync"

	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

type LeastConnections struct {
	mu     sync.Mutex
	routes []routingdomain.Route
}

func NewLeastConnections(routes []routingdomain.Route) *LeastConnections {
	// Rotation happens in place, so the strategy owns its own copy.
	return &LeastConnections{routes: slices.Clone(routes)}
}

func (lc *LeastConnections) Next(
	_ context.Context,
	_ *infracontext.RequestContext,
	exclude map[routingdomain.RouteKey]struct{},
) *routingdomain.Route {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	n := len(lc.routes)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		selected := lc.routes[0]
		lc.routes = append(lc.routes[1:], lc.routes[0])
		if !isExcluded(selected.Key(), exclude) {
			return pick(selected)
		}
	}
	return nil
}

func (lc *LeastConnections) Name() string {
	return algorithm.LeastConnections
}
