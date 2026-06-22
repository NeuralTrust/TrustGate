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
	"errors"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing"
)

func newTestRegistry(t *testing.T, provider string) *registrydomain.Registry {
	t.Helper()
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		Type:      registrydomain.TypeLLM,
		LLMTarget: &registrydomain.LLMTarget{Provider: provider},
	}
}

func TestCandidateSet_AddMergesByRegistry(t *testing.T) {
	t.Parallel()
	reg := newTestRegistry(t, "openai")
	s := routing.NewCandidateSet()
	s.Add(routing.Candidate{Registry: reg, Allowed: []string{"gpt-5"}, Sources: []string{"role:a"}})
	s.Add(routing.Candidate{Registry: reg, Allowed: []string{"gpt-5", "gpt-5-mini"}, Default: "gpt-5", Sources: []string{"role:b"}})

	if s.Len() != 1 {
		t.Fatalf("expected 1 candidate, got %d", s.Len())
	}
	c, ok := s.ForRegistry(reg.ID)
	if !ok {
		t.Fatal("candidate not found by registry")
	}
	if len(c.Allowed) != 2 || c.Default != "gpt-5" {
		t.Fatalf("merge mismatch: %+v", c)
	}
	if len(c.Sources) != 2 {
		t.Fatalf("expected merged provenance, got %v", c.Sources)
	}
}

func TestCandidateSet_AddMergeDoesNotMutateSourceAllowLists(t *testing.T) {
	t.Parallel()
	reg := newTestRegistry(t, "openai")
	shared := make([]string, 1, 4)
	shared[0] = "gpt-5"
	snapshot := shared[:cap(shared)]
	want := append([]string(nil), snapshot...)

	s := routing.NewCandidateSet()
	s.Add(routing.Candidate{Registry: reg, Allowed: shared})
	s.Add(routing.Candidate{Registry: reg, Allowed: []string{"gpt-5-mini"}})

	for i, m := range snapshot {
		if m != want[i] {
			t.Fatalf("merge mutated the shared source slice at %d: %q", i, m)
		}
	}
	merged, _ := s.ForRegistry(reg.ID)
	if len(merged.Allowed) != 2 {
		t.Fatalf("expected merged allow-list, got %v", merged.Allowed)
	}
}

func TestCandidateSet_AddMergeOpenAllowListWins(t *testing.T) {
	t.Parallel()
	reg := newTestRegistry(t, "openai")
	s := routing.NewCandidateSet()
	s.Add(routing.Candidate{Registry: reg, Allowed: []string{"gpt-5"}})
	s.Add(routing.Candidate{Registry: reg})

	c, _ := s.ForRegistry(reg.ID)
	if c.Allowed != nil {
		t.Fatalf("expected open allow-list after merge, got %v", c.Allowed)
	}
}

func TestCandidateSet_ResolveQualified(t *testing.T) {
	t.Parallel()
	openai := newTestRegistry(t, "openai")
	azure := newTestRegistry(t, "azure")
	s := routing.NewCandidateSet()
	s.Add(routing.Candidate{Registry: openai, Allowed: []string{"gpt-5"}})
	s.Add(routing.Candidate{Registry: azure, Allowed: []string{"gpt-5"}})

	out, err := s.ResolveIntent(routing.Intent{Provider: "openai", Model: "gpt-5"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Len() != 1 || !out.HasRegistry(openai.ID) {
		t.Fatalf("expected only openai candidate, got %d", out.Len())
	}
	c, _ := out.ForRegistry(openai.ID)
	if c.Model != "gpt-5" {
		t.Fatalf("expected pinned model, got %q", c.Model)
	}
}

func TestCandidateSet_ResolveQualifiedDeniedModel(t *testing.T) {
	t.Parallel()
	openai := newTestRegistry(t, "openai")
	s := routing.NewCandidateSet()
	s.Add(routing.Candidate{Registry: openai, Allowed: []string{"gpt-5"}})

	_, err := s.ResolveIntent(routing.Intent{Provider: "openai", Model: "gpt-4o"})
	if !errors.Is(err, routing.ErrModelDenied) {
		t.Fatalf("expected ErrModelDenied, got %v", err)
	}
}

func TestCandidateSet_ResolveQualifiedUnknownProvider(t *testing.T) {
	t.Parallel()
	openai := newTestRegistry(t, "openai")
	s := routing.NewCandidateSet()
	s.Add(routing.Candidate{Registry: openai})

	_, err := s.ResolveIntent(routing.Intent{Provider: "anthropic", Model: "claude-4"})
	if !errors.Is(err, routing.ErrModelDenied) {
		t.Fatalf("expected ErrModelDenied, got %v", err)
	}
}

func TestCandidateSet_ResolveShortModelSingleProvider(t *testing.T) {
	t.Parallel()
	a := newTestRegistry(t, "openai")
	b := newTestRegistry(t, "openai")
	s := routing.NewCandidateSet()
	s.Add(routing.Candidate{Registry: a, Allowed: []string{"gpt-5"}})
	s.Add(routing.Candidate{Registry: b, Allowed: []string{"gpt-5", "gpt-5-mini"}})

	out, err := s.ResolveIntent(routing.Intent{Model: "gpt-5"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Len() != 2 {
		t.Fatalf("same-provider registries must stay balanceable, got %d", out.Len())
	}
}

func TestCandidateSet_ResolveShortModelAmbiguous(t *testing.T) {
	t.Parallel()
	s := routing.NewCandidateSet()
	s.Add(routing.Candidate{Registry: newTestRegistry(t, "openai"), Allowed: []string{"gpt-5"}})
	s.Add(routing.Candidate{Registry: newTestRegistry(t, "azure"), Allowed: []string{"gpt-5"}})

	_, err := s.ResolveIntent(routing.Intent{Model: "gpt-5"})
	if !errors.Is(err, routing.ErrAmbiguousModel) {
		t.Fatalf("expected ErrAmbiguousModel, got %v", err)
	}
	if !strings.Contains(err.Error(), "azure/gpt-5") || !strings.Contains(err.Error(), "openai/gpt-5") {
		t.Fatalf("error must list qualified alternatives, got %q", err.Error())
	}
}

func TestCandidateSet_ResolveShortModelDenied(t *testing.T) {
	t.Parallel()
	s := routing.NewCandidateSet()
	s.Add(routing.Candidate{Registry: newTestRegistry(t, "openai"), Allowed: []string{"gpt-5"}})

	_, err := s.ResolveIntent(routing.Intent{Model: "claude-4"})
	if !errors.Is(err, routing.ErrModelDenied) {
		t.Fatalf("expected ErrModelDenied, got %v", err)
	}
}

func TestCandidateSet_ZeroIntentKeepsSet(t *testing.T) {
	t.Parallel()
	s := routing.NewCandidateSet()
	s.Add(routing.Candidate{Registry: newTestRegistry(t, "openai")})

	out, err := s.ResolveIntent(routing.Intent{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != s {
		t.Fatal("zero intent must keep the original set")
	}
}
