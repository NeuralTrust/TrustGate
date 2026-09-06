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

func TestStoreGovernanceEnabled_OnlyEnterprise(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tier string
		want bool
	}{
		{tier: "enterprise", want: true},
		{tier: "Enterprise", want: true},
		{tier: "free", want: false},
		{tier: "standard", want: false},
		{tier: "", want: false},
	}
	for _, tc := range cases {
		g := &Gateway{Entitlements: Entitlements{Tier: tc.tier}}
		if got := g.StoreGovernanceEnabled(); got != tc.want {
			t.Fatalf("tier %q: StoreGovernanceEnabled = %v, want %v", tc.tier, got, tc.want)
		}
	}
	var nilGateway *Gateway
	if nilGateway.StoreGovernanceEnabled() {
		t.Fatal("a nil gateway must not report governance")
	}
}

// TestStoreMode_SelfServiceIgnoresMetadata guards the product rule: on a
// non-enterprise gateway the Store is always open, whatever mode is stamped in
// metadata. The stamped value stays readable through ConfiguredStoreMode so an
// admin's setting is not lost (it applies once the plan includes governance).
func TestStoreMode_SelfServiceIgnoresMetadata(t *testing.T) {
	t.Parallel()
	for _, tier := range []string{"free", "standard", ""} {
		for _, mode := range []string{StoreModeCurated, StoreModeNone} {
			g := &Gateway{
				Entitlements: Entitlements{Tier: tier},
				Metadata:     WithStoreMode(nil, mode),
			}
			if got := g.StoreMode(); got != StoreModeOpen {
				t.Fatalf("tier %q with %q stamped: StoreMode = %q, want open", tier, mode, got)
			}
			if got := g.ConfiguredStoreMode(); got != mode {
				t.Fatalf("tier %q: ConfiguredStoreMode = %q, want %q", tier, got, mode)
			}
		}
	}
}

func TestStoreMode_EnterpriseHonoursMetadata(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{StoreModeOpen, StoreModeCurated, StoreModeNone} {
		g := &Gateway{
			Entitlements: Entitlements{Tier: "enterprise"},
			Metadata:     WithStoreMode(nil, mode),
		}
		if got := g.StoreMode(); got != mode {
			t.Fatalf("enterprise with %q stamped: StoreMode = %q", mode, got)
		}
	}
	unstamped := &Gateway{Entitlements: Entitlements{Tier: "enterprise"}}
	if got := unstamped.StoreMode(); got != StoreModeOpen {
		t.Fatalf("enterprise without a stamp must default to open, got %q", got)
	}
	var nilGateway *Gateway
	if got := nilGateway.StoreMode(); got != StoreModeOpen {
		t.Fatalf("nil gateway StoreMode = %q, want open", got)
	}
}
