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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
)

func makeBackends(names ...string) []*registry.Registry {
	out := make([]*registry.Registry, len(names))
	for i, name := range names {
		out[i] = &registry.Registry{ID: ids.New[ids.RegistryKind](), Name: name, LLMTarget: &registry.LLMTarget{Provider: "openai"}}
	}
	return out
}

func makeRoutes(names ...string) []routingdomain.Route {
	registries := makeBackends(names...)
	out := make([]routingdomain.Route, len(registries))
	for i, reg := range registries {
		out[i] = routingdomain.RouteForRegistry(reg)
	}
	return out
}

func modelRoutes(models ...string) []routingdomain.Route {
	shared := makeBackends("shared")[0]
	out := make([]routingdomain.Route, len(models))
	for i, model := range models {
		out[i] = routingdomain.Route{Registry: shared, Model: model, Weight: 1}
	}
	return out
}

func excludeRoutes(routes ...routingdomain.Route) map[routingdomain.RouteKey]struct{} {
	out := make(map[routingdomain.RouteKey]struct{}, len(routes))
	for _, route := range routes {
		out[route.Key()] = struct{}{}
	}
	return out
}

func routeName(t *testing.T, route *routingdomain.Route) string {
	t.Helper()
	if route == nil || route.Registry == nil {
		t.Fatal("expected a route with a registry")
	}
	return route.Registry.Name
}

func TestRoundRobin_RotatesThroughRoutes(t *testing.T) {
	t.Parallel()
	rr := NewRoundRobin(makeRoutes("a", "b", "c"))
	got := []string{}
	for i := 0; i < 6; i++ {
		got = append(got, routeName(t, rr.Next(context.Background(), nil, nil)))
	}
	want := []string{"a", "b", "c", "a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d: got %q, want %q (full sequence: %v)", i, got[i], want[i], got)
		}
	}
}

func TestRoundRobin_RotatesThroughModelsOfOneRegistry(t *testing.T) {
	t.Parallel()
	rr := NewRoundRobin(modelRoutes("gpt-4o-mini", "gpt-5"))
	got := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		route := rr.Next(context.Background(), nil, nil)
		if route == nil {
			t.Fatalf("step %d: expected a route", i)
		}
		got = append(got, route.Model)
	}
	want := []string{"gpt-4o-mini", "gpt-5", "gpt-4o-mini", "gpt-5"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d: got %q, want %q (full sequence: %v)", i, got[i], want[i], got)
		}
	}
}

func TestRoundRobin_ExcludingOneModelKeepsTheSibling(t *testing.T) {
	t.Parallel()
	routes := modelRoutes("gpt-4o-mini", "gpt-5")
	rr := NewRoundRobin(routes)
	exclude := excludeRoutes(routes[0])
	for i := 0; i < 4; i++ {
		route := rr.Next(context.Background(), nil, exclude)
		if route == nil || route.Model != "gpt-5" {
			t.Fatalf("step %d: expected the sibling route on the same registry, got %+v", i, route)
		}
	}
}

func TestRoundRobin_SkipsExcluded(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("a", "b", "c")
	rr := NewRoundRobin(routes)
	exclude := excludeRoutes(routes[0], routes[1])
	for i := 0; i < 4; i++ {
		route := rr.Next(context.Background(), nil, exclude)
		if route == nil || routeName(t, route) != "c" {
			t.Fatalf("step %d: expected only non-excluded route 'c', got %+v", i, route)
		}
	}
}

func TestRoundRobin_AllExcludedReturnsNil(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("a", "b")
	rr := NewRoundRobin(routes)
	if rr.Next(context.Background(), nil, excludeRoutes(routes...)) != nil {
		t.Fatal("expected nil when every route is excluded")
	}
}

func TestWeightedRoundRobin_AllExcludedReturnsNil(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("a", "b")
	wrr := NewWeightedRoundRobin(routes)
	if wrr.Next(context.Background(), nil, excludeRoutes(routes...)) != nil {
		t.Fatal("expected nil when every weighted route is excluded")
	}
}

func TestLeastConnections_SkipsExcluded(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("a", "b", "c")
	lc := NewLeastConnections(routes)
	route := lc.Next(context.Background(), nil, excludeRoutes(routes[0]))
	if route == nil || routeName(t, route) == "a" {
		t.Fatalf("expected a non-excluded route, got %+v", route)
	}
}

func TestRoundRobin_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	rr := NewRoundRobin(nil)
	if rr.Next(context.Background(), nil, nil) != nil {
		t.Fatal("Next on empty must return nil")
	}
}

func TestRoundRobin_Name(t *testing.T) {
	t.Parallel()
	if name := (&RoundRobin{}).Name(); name != "round-robin" {
		t.Fatalf("Name() = %q", name)
	}
}

func TestRandom_PicksOneOfTheRoutes(t *testing.T) {
	t.Parallel()
	r := NewRandom(makeRoutes("a", "b", "c"))
	seen := map[string]bool{}
	for i := 0; i < 30; i++ {
		route := r.Next(context.Background(), nil, nil)
		if route == nil {
			break
		}
		seen[routeName(t, route)] = true
	}
	if len(seen) == 0 {
		t.Fatal("Random.Next never returned a backend")
	}
	for name := range seen {
		if name != "a" && name != "b" && name != "c" {
			t.Fatalf("Random returned unexpected backend %q", name)
		}
	}
}

func TestRandom_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	if NewRandom(nil).Next(context.Background(), nil, nil) != nil {
		t.Fatal("Random on empty must return nil")
	}
}

func TestRandom_Name(t *testing.T) {
	t.Parallel()
	if name := (&Random{}).Name(); name != "random" {
		t.Fatalf("Name() = %q", name)
	}
}

func TestWeightedRoundRobin_RespectsWeights(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("heavy", "light")
	routes[0].Weight = 3
	routes[1].Weight = 1
	wrr := NewWeightedRoundRobin(routes)
	counts := map[string]int{}
	for i := 0; i < 40; i++ {
		route := wrr.Next(context.Background(), nil, nil)
		if route == nil {
			break
		}
		counts[routeName(t, route)]++
	}
	if counts["heavy"] <= counts["light"] {
		t.Fatalf("heavy=%d should outnumber light=%d", counts["heavy"], counts["light"])
	}
}

func TestWeightedRoundRobin_WeighsModelsOfOneRegistryIndependently(t *testing.T) {
	t.Parallel()
	routes := modelRoutes("gpt-4o-mini", "gpt-5")
	routes[0].Weight = 4
	routes[1].Weight = 1
	wrr := NewWeightedRoundRobin(routes)
	counts := map[string]int{}
	for i := 0; i < 50; i++ {
		route := wrr.Next(context.Background(), nil, nil)
		if route == nil {
			break
		}
		counts[route.Model]++
	}
	if counts["gpt-4o-mini"] <= counts["gpt-5"] {
		t.Fatalf("the heavier model route should win: %v", counts)
	}
	if counts["gpt-5"] == 0 {
		t.Fatalf("the lighter model route should still get traffic: %v", counts)
	}
}

func TestWeightedRoundRobin_ZeroWeightsServeAsWeightOne(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("a", "b")
	routes[0].Weight = 0
	routes[1].Weight = 0
	wrr := NewWeightedRoundRobin(routes)
	counts := map[string]int{}
	for i := 0; i < 10; i++ {
		route := wrr.Next(context.Background(), nil, nil)
		if route == nil {
			t.Fatal("WRR with zero weights must keep serving traffic (weight 0 acts as 1)")
			return
		}
		counts[routeName(t, route)]++
	}
	if counts["a"] == 0 || counts["b"] == 0 {
		t.Fatalf("both routes should receive traffic: %v", counts)
	}
}

func TestWeightedRoundRobin_Name(t *testing.T) {
	t.Parallel()
	if name := (&WeightedRoundRobin{}).Name(); name != "weighted-round-robin" {
		t.Fatalf("Name() = %q", name)
	}
}

func TestLeastConnections_NameAndRotation(t *testing.T) {
	t.Parallel()
	lc := NewLeastConnections(makeRoutes("a", "b", "c"))
	if lc.Name() != "least-connections" {
		t.Fatalf("Name() = %q", lc.Name())
	}
	got := []string{}
	for i := 0; i < 3; i++ {
		got = append(got, routeName(t, lc.Next(context.Background(), nil, nil)))
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("expected a,b,c got %v", got)
	}
}

func TestSemantic_NoConfigReturnsFirstRoute(t *testing.T) {
	t.Parallel()
	s := NewSemantic(nil, makeRoutes("a", "b"), nil, nil)
	route := s.Next(context.Background(), nil, nil)
	if route == nil || routeName(t, route) != "a" {
		t.Fatalf("expected first route a, got %+v", route)
	}
}

func TestSemantic_Name(t *testing.T) {
	t.Parallel()
	if name := (&Semantic{}).Name(); name != "semantic" {
		t.Fatalf("Name() = %q", name)
	}
}

func TestSemantic_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	if NewSemantic(nil, nil, nil, nil).Next(context.Background(), nil, nil) != nil {
		t.Fatal("empty Semantic.Next must return nil")
	}
}

func TestSemantic_SingleRoute(t *testing.T) {
	t.Parallel()
	s := NewSemantic(nil, makeRoutes("only"), nil, nil)
	got := s.Next(context.Background(), nil, nil)
	if got == nil || routeName(t, got) != "only" {
		t.Fatalf("expected 'only', got %+v", got)
	}
}

func TestExtractPromptFromRequest(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{
			name: "prompt field",
			body: `{"prompt":"hello"}`,
			want: "hello",
		},
		{
			name: "last user before tool messages",
			body: `{
				"messages":[
					{"role":"system","content":"you are a weather assistant"},
					{"role":"user","content":"What is the weather like in Beijing?"},
					{"role":"assistant","content":null,"tool_calls":[{"type":"function","function":{"name":"get_weather"}}]},
					{"role":"tool","content":"{\"temp\":22,\"condition\":\"sunny\"}"}
				]
			}`,
			want: "What is the weather like in Beijing?",
		},
		{
			name: "fallback last message when no user role",
			body: `{"messages":[{"role":"system","content":"sys"},{"role":"assistant","content":"reply"}]}`,
			want: "reply",
		},
		{
			name:    "empty body",
			body:    "",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := extractPromptFromRequest([]byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
