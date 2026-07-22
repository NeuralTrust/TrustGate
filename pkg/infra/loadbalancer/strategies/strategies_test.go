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
)

func makeBackends(names ...string) []*registry.Registry {
	out := make([]*registry.Registry, len(names))
	for i, name := range names {
		out[i] = &registry.Registry{ID: ids.New[ids.RegistryKind](), Name: name, LLMTarget: &registry.LLMTarget{Provider: "openai"}}
	}
	return out
}

func TestRoundRobin_RotatesThroughBackends(t *testing.T) {
	t.Parallel()
	rr := NewRoundRobin(makeBackends("a", "b", "c"))
	got := []string{}
	for i := 0; i < 6; i++ {
		got = append(got, rr.Next(context.Background(), nil, nil).Name)
	}
	want := []string{"a", "b", "c", "a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d: got %q, want %q (full sequence: %v)", i, got[i], want[i], got)
		}
	}
}

func TestRoundRobin_SkipsExcluded(t *testing.T) {
	t.Parallel()
	registries := makeBackends("a", "b", "c")
	rr := NewRoundRobin(registries)
	exclude := map[ids.RegistryID]struct{}{registries[0].ID: {}, registries[1].ID: {}}
	for i := 0; i < 4; i++ {
		b := rr.Next(context.Background(), nil, exclude)
		if b == nil || b.Name != "c" {
			t.Fatalf("step %d: expected only non-excluded backend 'c', got %+v", i, b)
		}
	}
}

func TestRoundRobin_AllExcludedReturnsNil(t *testing.T) {
	t.Parallel()
	registries := makeBackends("a", "b")
	rr := NewRoundRobin(registries)
	exclude := map[ids.RegistryID]struct{}{registries[0].ID: {}, registries[1].ID: {}}
	if rr.Next(context.Background(), nil, exclude) != nil {
		t.Fatal("expected nil when every backend is excluded")
	}
}

func TestWeightedRoundRobin_AllExcludedReturnsNil(t *testing.T) {
	t.Parallel()
	registries := makeBackends("a", "b")
	wrr := NewWeightedRoundRobin(registries, nil)
	exclude := map[ids.RegistryID]struct{}{registries[0].ID: {}, registries[1].ID: {}}
	if wrr.Next(context.Background(), nil, exclude) != nil {
		t.Fatal("expected nil when every weighted backend is excluded")
	}
}

func TestLeastConnections_SkipsExcluded(t *testing.T) {
	t.Parallel()
	registries := makeBackends("a", "b", "c")
	lc := NewLeastConnections(registries)
	exclude := map[ids.RegistryID]struct{}{registries[0].ID: {}}
	b := lc.Next(context.Background(), nil, exclude)
	if b == nil || b.Name == "a" {
		t.Fatalf("expected a non-excluded backend, got %+v", b)
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

func TestRandom_PicksOneOfTheBackends(t *testing.T) {
	t.Parallel()
	r := NewRandom(makeBackends("a", "b", "c"))
	seen := map[string]bool{}
	for i := 0; i < 30; i++ {
		b := r.Next(context.Background(), nil, nil)
		if b == nil {
			break
		}
		seen[b.Name] = true
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
	registries := []*registry.Registry{
		{ID: ids.New[ids.RegistryKind](), Name: "heavy", LLMTarget: &registry.LLMTarget{Provider: "openai"}},
		{ID: ids.New[ids.RegistryKind](), Name: "light", LLMTarget: &registry.LLMTarget{Provider: "openai"}},
	}
	weights := map[ids.RegistryID]int{
		registries[0].ID: 3,
		registries[1].ID: 1,
	}
	wrr := NewWeightedRoundRobin(registries, weights)
	counts := map[string]int{}
	for i := 0; i < 40; i++ {
		b := wrr.Next(context.Background(), nil, nil)
		if b == nil {
			break
		}
		counts[b.Name]++
	}
	if counts["heavy"] <= counts["light"] {
		t.Fatalf("heavy=%d should outnumber light=%d", counts["heavy"], counts["light"])
	}
}

func TestWeightedRoundRobin_ZeroWeightsServeAsWeightOne(t *testing.T) {
	t.Parallel()
	wrr := NewWeightedRoundRobin([]*registry.Registry{
		{ID: ids.New[ids.RegistryKind](), Name: "a"},
		{ID: ids.New[ids.RegistryKind](), Name: "b"},
	}, nil)
	counts := map[string]int{}
	for i := 0; i < 10; i++ {
		b := wrr.Next(context.Background(), nil, nil)
		if b == nil {
			t.Fatal("WRR with zero weights must keep serving traffic (weight 0 acts as 1)")
			return
		}
		counts[b.Name]++
	}
	if counts["a"] == 0 || counts["b"] == 0 {
		t.Fatalf("both registries should receive traffic: %v", counts)
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
	lc := NewLeastConnections(makeBackends("a", "b", "c"))
	if lc.Name() != "least-connections" {
		t.Fatalf("Name() = %q", lc.Name())
	}
	got := []string{}
	for i := 0; i < 3; i++ {
		got = append(got, lc.Next(context.Background(), nil, nil).Name)
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("expected a,b,c got %v", got)
	}
}

func TestSemantic_NoConfigReturnsFirstRegistry(t *testing.T) {
	t.Parallel()
	s := NewSemantic(nil, makeBackends("a", "b"), nil, nil)
	b := s.Next(context.Background(), nil, nil)
	if b == nil || b.Name != "a" {
		t.Fatalf("expected first backend a, got %+v", b)
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

func TestSemantic_SingleRegistry(t *testing.T) {
	t.Parallel()
	s := NewSemantic(nil, makeBackends("only"), nil, nil)
	got := s.Next(context.Background(), nil, nil)
	if got == nil || got.Name != "only" {
		t.Fatalf("expected 'only', got %+v", got)
	}
}
