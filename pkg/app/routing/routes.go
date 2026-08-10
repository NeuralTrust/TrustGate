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
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
)

// The result is request-independent because balancers are cached per consumer.
func BuildPoolRoutes(rc *appconsumer.RoutableConsumer) []routingdomain.Route {
	if rc == nil || rc.Consumer == nil {
		return nil
	}
	policies := rc.Consumer.ModelPolicies
	lbCfg := rc.Consumer.LBConfig
	if lbCfg == nil || !lbCfg.Enabled || len(lbCfg.Members) == 0 {
		return registryRoutes(rc, policies)
	}
	byID := registriesByID(rc)
	routes := make([]routingdomain.Route, 0, len(lbCfg.Members))
	for _, member := range lbCfg.Members {
		reg, ok := byID[member.RegistryID]
		if !ok {
			continue
		}
		policy, _ := policies.For(reg.ID)
		routes = append(routes, routingdomain.Route{
			Registry: reg,
			Model:    member.RouteModel(),
			Allowed:  memberAllowed(member, policy),
			Default:  routeDefault(member, policy),
			Weight:   member.RouteWeight(rc.Consumer.WeightFor(reg.ID)),
		})
	}
	if len(routes) == 0 {
		return registryRoutes(rc, policies)
	}
	return routes
}

func registryRoutes(
	rc *appconsumer.RoutableConsumer,
	policies consumerdomain.ModelPolicies,
) []routingdomain.Route {
	routes := make([]routingdomain.Route, 0, len(rc.Registries))
	for _, reg := range rc.Registries {
		policy, _ := policies.For(reg.ID)
		routes = append(routes, routingdomain.Route{
			Registry: reg,
			Allowed:  policy.Allowed,
			Default:  policy.Default,
			Weight:   rc.Consumer.WeightFor(reg.ID),
		})
	}
	return routes
}

func routeDefault(member consumerdomain.LBPoolMember, policy consumerdomain.ModelPolicy) string {
	if model := member.RouteModel(); model != "" {
		return model
	}
	return memberDefault(member, policy)
}

// Auto routing drops candidates without a default, so a pinned member model must serve as one.
func memberPinnedModels(lbCfg *consumerdomain.LBConfig) map[ids.RegistryID]string {
	if lbCfg == nil || !lbCfg.Enabled || len(lbCfg.Members) == 0 {
		return nil
	}
	pinned := make(map[ids.RegistryID]string, len(lbCfg.Members))
	for _, member := range lbCfg.Members {
		model := member.RouteModel()
		if model == "" {
			continue
		}
		if _, seen := pinned[member.RegistryID]; seen {
			continue
		}
		pinned[member.RegistryID] = model
	}
	if len(pinned) == 0 {
		return nil
	}
	return pinned
}
