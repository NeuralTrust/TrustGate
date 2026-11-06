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
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

func TestEveryoneRegistryCleaner(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	withBoth, _ := storeaccessdomain.NewEveryone(gw, "curated", []storeaccessdomain.EveryoneGrant{{CatalogCode: "github"}, {CatalogCode: "snowflake", RegistryID: reg}}, nil)
	repo := &fakeEveryoneRepo{items: map[ids.GatewayID]*storeaccessdomain.Everyone{gw: withBoth}}
	cleaner := NewEveryoneRegistryCleaner(repo)

	if err := cleaner.DeleteByRegistry(context.Background(), gw, reg); err != nil {
		t.Fatalf("DeleteByRegistry: %v", err)
	}
	if got := repo.items[gw]; got == nil || len(got.Grants) != 1 || got.Grants[0].CatalogCode != "github" {
		t.Fatalf("the deleted registry's grant must go and the rest stay, got %+v", got)
	}

	only, _ := storeaccessdomain.NewEveryone(gw, "curated", []storeaccessdomain.EveryoneGrant{{CatalogCode: "snowflake", RegistryID: reg}}, nil)
	repo.items[gw] = only
	if err := cleaner.DeleteByRegistry(context.Background(), gw, reg); err != nil {
		t.Fatalf("DeleteByRegistry: %v", err)
	}
	if _, ok := repo.items[gw]; ok || len(repo.deleted) != 1 {
		t.Fatalf("a curated object left without grants must be removed, items=%+v deleted=%d", repo.items, len(repo.deleted))
	}

	if err := cleaner.DeleteByRegistry(context.Background(), ids.New[ids.GatewayKind](), reg); err != nil {
		t.Fatalf("a gateway without Everyone is a no-op, got %v", err)
	}
}
