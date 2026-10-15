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

package gateway

import "testing"

// TestStoreMode_DefaultsToCuratedOnEveryTier guards the governed default: a
// gateway nobody has configured grants nobody anything, whatever its plan.
// Opening the whole catalog is a decision an admin makes, and an org that has
// decided nothing must not have it made for them.
func TestStoreMode_DefaultsToCuratedOnEveryTier(t *testing.T) {
	t.Parallel()
	for _, tier := range []string{"free", "standard", "enterprise", ""} {
		g := &Gateway{Entitlements: Entitlements{Tier: tier}}
		if got := g.StoreMode(); got != StoreModeCurated {
			t.Fatalf("tier %q unstamped: StoreMode = %q, want curated", tier, got)
		}
	}
	var nilGateway *Gateway
	if got := nilGateway.StoreMode(); got != StoreModeCurated {
		t.Fatalf("nil gateway StoreMode = %q, want curated", got)
	}
}

// TestStoreMode_HonoursStampedModeOnEveryTier guards the corrected product rule:
// governance is not a plan entitlement. Once an admin — on any tier, including
// self-service — narrows the Store, the stamped mode is enforced.
func TestStoreMode_HonoursStampedModeOnEveryTier(t *testing.T) {
	t.Parallel()
	for _, tier := range []string{"free", "standard", "enterprise", ""} {
		for _, mode := range []string{StoreModeOpen, StoreModeCurated, StoreModeNone} {
			g := &Gateway{
				Entitlements: Entitlements{Tier: tier},
				Metadata:     WithStoreMode(nil, mode),
			}
			if got := g.StoreMode(); got != mode {
				t.Fatalf("tier %q with %q stamped: StoreMode = %q", tier, mode, got)
			}
		}
	}
}
