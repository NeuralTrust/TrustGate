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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func testRegistry() *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		Type:      registrydomain.TypeLLM,
		LLMTarget: &registrydomain.LLMTarget{Provider: "openai"},
	}
}

func TestRoute_KeySeparatesModelsOnOneRegistry(t *testing.T) {
	t.Parallel()
	reg := testRegistry()
	first := Route{Registry: reg, Model: "gpt-4o-mini"}
	second := Route{Registry: reg, Model: "gpt-5"}

	if first.Key() == second.Key() {
		t.Fatal("two models on one registry must not share a route key")
	}
	if first.Key() != (Route{Registry: reg, Model: "gpt-4o-mini"}).Key() {
		t.Fatal("the same registry and model must produce the same key")
	}
	exclude := map[RouteKey]struct{}{first.Key(): {}}
	if _, excluded := exclude[second.Key()]; excluded {
		t.Fatal("excluding one route must not exclude the registry's other routes")
	}
}

func TestRoute_ZeroValues(t *testing.T) {
	t.Parallel()
	var route Route
	if route.Key() != (RouteKey{}) {
		t.Fatalf("Key() = %+v, want the zero key", route.Key())
	}
	if !route.RegistryID().IsNil() {
		t.Fatalf("RegistryID() = %s, want nil", route.RegistryID())
	}
	if route.EffectiveWeight() != DefaultRouteWeight {
		t.Fatalf("EffectiveWeight() = %d, want %d", route.EffectiveWeight(), DefaultRouteWeight)
	}
}

func TestRoute_EffectiveWeight(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		weight int
		want   int
	}{
		{name: "unset", weight: 0, want: DefaultRouteWeight},
		{name: "negative", weight: -3, want: DefaultRouteWeight},
		{name: "declared", weight: 6, want: 6},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			route := Route{Registry: testRegistry(), Weight: tc.weight}
			if got := route.EffectiveWeight(); got != tc.want {
				t.Fatalf("EffectiveWeight() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRouteForRegistry(t *testing.T) {
	t.Parallel()
	reg := testRegistry()
	route := RouteForRegistry(reg)
	if route.Model != "" {
		t.Fatalf("Model = %q, want unpinned", route.Model)
	}
	if route.RegistryID() != reg.ID {
		t.Fatalf("RegistryID() = %s, want %s", route.RegistryID(), reg.ID)
	}
	if route.EffectiveWeight() != DefaultRouteWeight {
		t.Fatalf("EffectiveWeight() = %d, want %d", route.EffectiveWeight(), DefaultRouteWeight)
	}
}

func TestDistinctRegistries(t *testing.T) {
	t.Parallel()
	shared := testRegistry()
	other := testRegistry()
	routes := []Route{
		{Registry: shared, Model: "gpt-4o-mini"},
		{Registry: shared, Model: "gpt-5"},
		{Registry: other},
		{Registry: nil},
	}

	got := DistinctRegistries(routes)

	if len(got) != 2 {
		t.Fatalf("DistinctRegistries() = %d registries, want 2", len(got))
	}
	if got[0].ID != shared.ID || got[1].ID != other.ID {
		t.Fatal("DistinctRegistries() must preserve first-seen order")
	}
}
