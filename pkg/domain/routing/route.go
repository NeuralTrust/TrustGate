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

package routing

import (
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const DefaultRouteWeight = 1

type RouteKey struct {
	RegistryID ids.RegistryID
	Model      string
}

type Route struct {
	Registry *registrydomain.Registry
	Model    string
	Allowed  []string
	Default  string
	Weight   int
}

func (r Route) Key() RouteKey {
	if r.Registry == nil {
		return RouteKey{}
	}
	return RouteKey{RegistryID: r.Registry.ID, Model: r.Model}
}

func (r Route) RegistryID() ids.RegistryID {
	if r.Registry == nil {
		return ids.RegistryID{}
	}
	return r.Registry.ID
}

func (r Route) EffectiveWeight() int {
	if r.Weight <= 0 {
		return DefaultRouteWeight
	}
	return r.Weight
}

func RouteForRegistry(reg *registrydomain.Registry) Route {
	return Route{Registry: reg, Weight: DefaultRouteWeight}
}

func DistinctRegistries(routes []Route) []*registrydomain.Registry {
	out := make([]*registrydomain.Registry, 0, len(routes))
	seen := make(map[ids.RegistryID]struct{}, len(routes))
	for _, route := range routes {
		if route.Registry == nil {
			continue
		}
		if _, dup := seen[route.Registry.ID]; dup {
			continue
		}
		seen[route.Registry.ID] = struct{}{}
		out = append(out, route.Registry)
	}
	return out
}
