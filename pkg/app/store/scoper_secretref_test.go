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

package store

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type copyingMaterializer struct{ gateway ids.GatewayID }

func (m *copyingMaterializer) Registries(_ context.Context, gw ids.GatewayID, byID map[ids.RegistryID]*registrydomain.Registry) map[ids.RegistryID]*registrydomain.Registry {
	m.gateway = gw
	out := map[ids.RegistryID]*registrydomain.Registry{}
	for id, r := range byID {
		c := *r
		c.Name = "resolved:" + r.Name
		out[id] = &c
	}
	return out
}

func TestScoperMaterializesShelvesInOrder(t *testing.T) {
	t.Parallel()
	m := &copyingMaterializer{}
	s := &scoper{secretRefs: m}
	gw := ids.New[ids.GatewayKind]()
	a := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), Name: "a"}
	b := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), Name: "b"}
	got := s.materialize(context.Background(), gw, []*registrydomain.Registry{a, nil, b})
	if len(got) != 3 || got[0].Name != "resolved:a" || got[1] != nil || got[2].Name != "resolved:b" || m.gateway != gw {
		t.Fatalf("materialized %v", got)
	}
	if a.Name != "a" {
		t.Fatal("the shelf registry was modified")
	}
	if out := (&scoper{}).materialize(context.Background(), gw, []*registrydomain.Registry{a}); out[0] != a {
		t.Fatal("without a materializer the shelves are returned as listed")
	}
}
