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
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
)

func isExcluded(key routingdomain.RouteKey, exclude map[routingdomain.RouteKey]struct{}) bool {
	if len(exclude) == 0 {
		return false
	}
	_, ok := exclude[key]
	return ok
}

func filterExcluded(
	routes []routingdomain.Route,
	exclude map[routingdomain.RouteKey]struct{},
) []routingdomain.Route {
	if len(exclude) == 0 {
		return routes
	}
	out := make([]routingdomain.Route, 0, len(routes))
	for _, route := range routes {
		if !isExcluded(route.Key(), exclude) {
			out = append(out, route)
		}
	}
	return out
}

// Copies the route so callers cannot mutate the pool through the returned pointer.
func pick(route routingdomain.Route) *routingdomain.Route {
	return &route
}
