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

package consumer

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestStoreConsumerIDIsStableAndParseable(t *testing.T) {
	id := StoreConsumerID()
	if id == (ids.ConsumerID{}) {
		t.Fatal("store consumer id must parse to a non-zero sentinel")
	}
	if StoreConsumerID() != id {
		t.Fatal("store consumer id must be stable across calls")
	}
}

func TestIsStoreSlug(t *testing.T) {
	if !IsStoreSlug(StoreSlug) {
		t.Fatalf("IsStoreSlug(%q) must be true", StoreSlug)
	}
	for _, s := range []string{"", "storefront", "X84Yhsy8", "catalog"} {
		if IsStoreSlug(s) {
			t.Fatalf("IsStoreSlug(%q) must be false", s)
		}
	}
}

func TestBuildStoreConsumer(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	c := BuildStoreConsumer(gw)

	if !IsStoreConsumer(c) {
		t.Fatal("BuildStoreConsumer must produce a recognisable Store consumer")
	}
	if c.GatewayID != gw {
		t.Fatalf("store consumer must be stamped with the addressed gateway, got %v", c.GatewayID)
	}
	if c.Slug != StoreSlug {
		t.Fatalf("store slug = %q, want %q", c.Slug, StoreSlug)
	}
	if c.Type != TypeMCP {
		t.Fatalf("store type = %v, want MCP", c.Type)
	}
	if c.RoutingMode != RoutingModeInline {
		t.Fatalf("store routing mode = %v, want inline", c.RoutingMode)
	}
	if !c.Active {
		t.Fatal("store consumer must be active")
	}
	if len(c.AuthIDs) != 0 || len(c.RegistryIDs) != 0 || len(c.RoleIDs) != 0 {
		t.Fatalf("store consumer must carry no auths/registries/roles, got %+v", c)
	}
}

func TestIsStoreConsumerRejectsRegularConsumer(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	c, err := New(CreateParams{GatewayID: gw, Name: "regular", Type: TypeMCP})
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	if IsStoreConsumer(c) {
		t.Fatal("a regular consumer must not be recognised as the Store")
	}
	if IsStoreConsumer(nil) {
		t.Fatal("nil must not be recognised as the Store")
	}
}
