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

package proxy

import (
	"context"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type exclusionListing map[string]appcatalog.Verdict

func (l exclusionListing) Lists(_ context.Context, providerCode, model string) appcatalog.Verdict {
	return l[providerCode+":"+model]
}

func (l exclusionListing) InvalidateCache() {}

func exclusionRegistry(name, provider string) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		Name:      name,
		Type:      registrydomain.TypeLLM,
		LLMTarget: &registrydomain.LLMTarget{Provider: provider},
	}
}

func exclusionConsumer(policies domainconsumer.ModelPolicies, registries ...*registrydomain.Registry) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{
		Consumer:   &domainconsumer.Consumer{ID: ids.New[ids.ConsumerKind](), ModelPolicies: policies},
		Registries: registries,
	}
}

func TestExclusionReasonFor(t *testing.T) {
	t.Parallel()
	reg := exclusionRegistry("registry-openai", "openai")

	cases := []struct {
		name    string
		allowed []string
		model   string
		listing exclusionListing
		probed  bool
		want    exclusionReason
	}{
		{
			name:    "allow-list that does not match the model",
			allowed: []string{"claude-haiku-*"},
			model:   "claude-sonnet-4-5",
			want:    exclusionAllowList,
		},
		{
			name:    "allow-list that matches is not blamed on the catalog",
			allowed: []string{"gpt-*"},
			model:   "gpt-4.1",
			listing: exclusionListing{"openai:gpt-4.1": appcatalog.VerdictAbsent},
			want:    exclusionUnexplained,
		},
		{
			name:    "empty allow-list is a restriction, not an open scope",
			allowed: []string{},
			model:   "gpt-4.1",
			want:    exclusionAllowList,
		},
		{
			name:    "no allow-list and the catalog does not list the model",
			model:   "claude-sonnet-4-5",
			listing: exclusionListing{"openai:claude-sonnet-4-5": appcatalog.VerdictAbsent},
			want:    exclusionCatalogAbsent,
		},
		{
			name:    "no allow-list, no authoritative catalog, never probed",
			model:   "nope-9",
			listing: exclusionListing{},
			want:    exclusionUnexplained,
		},
		{
			name:    "no allow-list, no authoritative catalog, the provider itself rejected it",
			model:   "nope-9",
			listing: exclusionListing{},
			probed:  true,
			want:    exclusionProviderRejected,
		},
		{
			name:    "a glob request ref is never read as an allow-list miss",
			allowed: []string{"claude-haiku-*"},
			model:   "gpt-*",
			want:    exclusionUnexplained,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &forwarder{}
			if tc.listing != nil {
				f.listing = tc.listing
			}
			rc := exclusionConsumer(domainconsumer.ModelPolicies{reg.ID: {Allowed: tc.allowed}}, reg)
			probed := map[ids.RegistryID]struct{}{}
			if tc.probed {
				probed[reg.ID] = struct{}{}
			}
			if got := f.exclusionReasonFor(context.Background(), rc, reg, tc.model, probed); got != tc.want {
				t.Fatalf("exclusionReasonFor(%q) = %v, want %v", tc.model, got, tc.want)
			}
		})
	}
}

func TestModelExclusions_CoversFallbackBackendsWithoutRepeating(t *testing.T) {
	t.Parallel()
	bound := exclusionRegistry("registry-openai", "openai")
	rescue := exclusionRegistry("registry-vertex", "vertex")
	rc := exclusionConsumer(nil, bound)
	rc.Registries = []*registrydomain.Registry{bound}
	rc.FallbackBackends = []*registrydomain.Registry{bound, rescue}

	got := (&forwarder{}).modelExclusions(context.Background(), rc, "nope-9", nil)

	if len(got) != 2 {
		t.Fatalf("got %d exclusions, want one per distinct registry: %+v", len(got), got)
	}
	if got[0].label != "registry-openai" || got[1].label != "registry-vertex" {
		t.Fatalf("exclusions must follow the consumer's configured order, got %+v", got)
	}
}

func TestModelExclusions_NilConsumerYieldsNothing(t *testing.T) {
	t.Parallel()
	if got := (&forwarder{}).modelExclusions(context.Background(), nil, "nope-9", nil); got != nil {
		t.Fatalf("got %+v, want no exclusions for a nil consumer", got)
	}
}

func TestRegistryLabel_FallsBackToProvider(t *testing.T) {
	t.Parallel()
	if got := registryLabel(exclusionRegistry("", "openai")); got != "openai" {
		t.Fatalf("registryLabel = %q, want the provider code when the name is empty", got)
	}
	if got := registryLabel(exclusionRegistry("  ", "openai")); got != "openai" {
		t.Fatalf("registryLabel = %q, want a blank name treated as absent", got)
	}
}

func TestRenderExclusions_OmitsReasonsWhenNoneAreConcrete(t *testing.T) {
	t.Parallel()
	bare := renderExclusions([]registryExclusion{
		{label: "registry-openai", reason: exclusionUnexplained},
		{label: "registry-vertex", reason: exclusionUnexplained},
	})
	if bare != "registry-openai, registry-vertex" {
		t.Fatalf("render = %q, want bare labels when no reason is concrete", bare)
	}

	mixed := renderExclusions([]registryExclusion{
		{label: "registry-anthropic", reason: exclusionAllowList},
		{label: "registry-openai", reason: exclusionUnexplained},
	})
	want := "registry-anthropic: restricted by its model allow-list; registry-openai: not eligible for this request"
	if mixed != want {
		t.Fatalf("render = %q, want %q", mixed, want)
	}
}
