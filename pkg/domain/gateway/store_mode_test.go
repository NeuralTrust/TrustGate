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

// TestStoreMode_DefaultsToOpenOnEveryTier guards the zero-friction default: a
// gateway with nothing stamped is open whatever its plan, so a self-service
// user reaches "install Notion" without configuring anything.
func TestStoreMode_DefaultsToOpenOnEveryTier(t *testing.T) {
	t.Parallel()
	for _, tier := range []string{"free", "standard", "enterprise", ""} {
		g := &Gateway{Entitlements: Entitlements{Tier: tier}}
		if got := g.StoreMode(); got != StoreModeOpen {
			t.Fatalf("tier %q unstamped: StoreMode = %q, want open", tier, got)
		}
	}
	var nilGateway *Gateway
	if got := nilGateway.StoreMode(); got != StoreModeOpen {
		t.Fatalf("nil gateway StoreMode = %q, want open", got)
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
