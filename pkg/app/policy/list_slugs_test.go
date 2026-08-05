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

package policy_test

import (
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
)

func TestResolveListSlugs(t *testing.T) {
	t.Parallel()
	catalog := appplugins.Catalog{
		Groups: []appplugins.CatalogGroup{
			{
				Type: "Guardrails",
				Items: []appplugins.CatalogEntry{
					{Slug: "trustguard"},
					{Slug: "openai_moderation"},
				},
			},
			{
				Type: "Traffic Control",
				Items: []appplugins.CatalogEntry{
					{Slug: "rate_limiter"},
				},
			},
		},
	}

	t.Run("no filters", func(t *testing.T) {
		t.Parallel()
		slugs, restricted := apppolicy.ResolveListSlugs(catalog, nil, nil)
		if restricted || slugs != nil {
			t.Fatalf("got slugs=%v restricted=%v", slugs, restricted)
		}
	})

	t.Run("category only", func(t *testing.T) {
		t.Parallel()
		slugs, restricted := apppolicy.ResolveListSlugs(catalog, []string{"Guardrails"}, nil)
		if !restricted {
			t.Fatal("expected restricted")
		}
		assertStrings(t, slugs, []string{"openai_moderation", "trustguard"})
	})

	t.Run("type only", func(t *testing.T) {
		t.Parallel()
		slugs, restricted := apppolicy.ResolveListSlugs(catalog, nil, []string{"rate_limiter"})
		if !restricted {
			t.Fatal("expected restricted")
		}
		assertStrings(t, slugs, []string{"rate_limiter"})
	})

	t.Run("category and type intersection", func(t *testing.T) {
		t.Parallel()
		slugs, restricted := apppolicy.ResolveListSlugs(
			catalog,
			[]string{"Guardrails"},
			[]string{"trustguard", "rate_limiter"},
		)
		if !restricted {
			t.Fatal("expected restricted")
		}
		assertStrings(t, slugs, []string{"trustguard"})
	})

	t.Run("unknown category yields empty restricted set", func(t *testing.T) {
		t.Parallel()
		slugs, restricted := apppolicy.ResolveListSlugs(catalog, []string{"Missing"}, nil)
		if !restricted {
			t.Fatal("expected restricted")
		}
		if len(slugs) != 0 {
			t.Fatalf("expected empty slugs, got %v", slugs)
		}
	})
}

func assertStrings(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len got=%d want=%d (%v vs %v)", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %q want %q (full %v)", i, got[i], want[i], got)
		}
	}
}
