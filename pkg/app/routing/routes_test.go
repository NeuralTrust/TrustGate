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

package routing_test

import (
	"testing"

	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
)

func intPtr(v int) *int { return &v }

func TestBuildPoolRoutes_SameRegistryDistinctModels(t *testing.T) {
	t.Parallel()
	shared := newRegistry("openai")
	policies := consumerdomain.ModelPolicies{
		shared.ID: {Allowed: []string{"gpt-4o-mini", "gpt-5"}, Default: "gpt-4o-mini"},
	}
	rc := inlineConsumer([]*registrydomain.Registry{shared}, policies, &consumerdomain.LBConfig{
		Enabled: true,
		Members: []consumerdomain.LBPoolMember{
			{RegistryID: shared.ID, Model: "gpt-4o-mini"},
			{RegistryID: shared.ID, Model: "gpt-5", Weight: intPtr(4)},
		},
	})

	routes := approuting.BuildPoolRoutes(rc)

	if len(routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(routes))
	}
	if routes[0].Key() == routes[1].Key() {
		t.Fatalf("routes share an identity: %+v", routes[0].Key())
	}
	for i, want := range []string{"gpt-4o-mini", "gpt-5"} {
		if routes[i].Model != want {
			t.Fatalf("routes[%d].Model = %q, want %q", i, routes[i].Model, want)
		}
		if routes[i].Default != want {
			t.Fatalf("routes[%d].Default = %q, want %q", i, routes[i].Default, want)
		}
		if routes[i].RegistryID() != shared.ID {
			t.Fatalf("routes[%d] registry = %s, want %s", i, routes[i].RegistryID(), shared.ID)
		}
	}
	if routes[0].EffectiveWeight() != 1 {
		t.Fatalf("routes[0] weight = %d, want the consumer fallback 1", routes[0].EffectiveWeight())
	}
	if routes[1].EffectiveWeight() != 4 {
		t.Fatalf("routes[1] weight = %d, want the member weight 4", routes[1].EffectiveWeight())
	}
}

func TestBuildPoolRoutes_FallsBackToAttachedRegistries(t *testing.T) {
	t.Parallel()
	a := newRegistry("openai")
	b := newRegistry("anthropic")
	policies := consumerdomain.ModelPolicies{
		a.ID: {Allowed: []string{"gpt-5"}, Default: "gpt-5"},
		b.ID: {Allowed: []string{"claude-4"}, Default: "claude-4"},
	}
	tests := []struct {
		name string
		lb   *consumerdomain.LBConfig
	}{
		{name: "no lb config", lb: nil},
		{name: "lb disabled", lb: &consumerdomain.LBConfig{Enabled: false}},
		{name: "lb enabled without members", lb: &consumerdomain.LBConfig{Enabled: true}},
		{
			name: "members that are not attached",
			lb: &consumerdomain.LBConfig{
				Enabled: true,
				Members: []consumerdomain.LBPoolMember{{RegistryID: ids.New[ids.RegistryKind]()}},
			},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rc := inlineConsumer([]*registrydomain.Registry{a, b}, policies, tc.lb)

			routes := approuting.BuildPoolRoutes(rc)

			if len(routes) != 2 {
				t.Fatalf("routes = %d, want one per attached registry", len(routes))
			}
			for i, route := range routes {
				if route.Model != "" {
					t.Fatalf("routes[%d].Model = %q, want unpinned", i, route.Model)
				}
			}
			if routes[0].Default != "gpt-5" || routes[1].Default != "claude-4" {
				t.Fatalf("defaults = %q/%q, want the policy defaults", routes[0].Default, routes[1].Default)
			}
		})
	}
}

func TestBuildPoolRoutes_MemberModelsNarrowTheAllowList(t *testing.T) {
	t.Parallel()
	reg := newRegistry("openai")
	policies := consumerdomain.ModelPolicies{
		reg.ID: {Allowed: []string{"gpt-4o-mini", "gpt-5"}, Default: "gpt-5"},
	}
	rc := inlineConsumer([]*registrydomain.Registry{reg}, policies, &consumerdomain.LBConfig{
		Enabled: true,
		Members: []consumerdomain.LBPoolMember{
			{RegistryID: reg.ID, Models: []string{"gpt-4o-mini"}},
		},
	})

	routes := approuting.BuildPoolRoutes(rc)

	if len(routes) != 1 {
		t.Fatalf("routes = %d, want 1", len(routes))
	}
	if len(routes[0].Allowed) != 1 || routes[0].Allowed[0] != "gpt-4o-mini" {
		t.Fatalf("Allowed = %v, want the member narrowing", routes[0].Allowed)
	}
	if routes[0].Default != "gpt-4o-mini" {
		t.Fatalf("Default = %q, want the member narrowing to win over the policy default", routes[0].Default)
	}
}

func TestBuildPoolRoutes_NilConsumer(t *testing.T) {
	t.Parallel()
	if routes := approuting.BuildPoolRoutes(nil); routes != nil {
		t.Fatalf("routes = %v, want nil", routes)
	}
}

func TestResolver_AutoKeepsRegistryWhoseDefaultComesFromAMember(t *testing.T) {
	t.Parallel()
	reg := newRegistry("openai")
	policies := consumerdomain.ModelPolicies{
		reg.ID: {Allowed: []string{"gpt-4o-mini", "gpt-5"}},
	}
	rc := inlineConsumer([]*registrydomain.Registry{reg}, policies, &consumerdomain.LBConfig{
		Enabled: true,
		Members: []consumerdomain.LBPoolMember{
			{RegistryID: reg.ID, Model: "gpt-4o-mini"},
			{RegistryID: reg.ID, Model: "gpt-5"},
		},
	})

	cs, err := approuting.NewResolver().Resolve(approuting.ResolveInput{
		Intent:   routingdomain.Intent{Auto: true},
		Consumer: rc,
	})
	if err != nil {
		t.Fatalf("auto resolution dropped a registry whose default comes from a member: %v", err)
	}
	if !cs.HasRegistry(reg.ID) {
		t.Fatalf("candidates = %v, want the registry to survive auto filtering", cs.Registries())
	}
}
