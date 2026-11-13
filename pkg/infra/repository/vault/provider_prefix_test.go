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

package vault_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	vaultrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/vault"
)

func TestRedisRepository_ProviderPrefixListsAndDeletesEveryPrincipal(t *testing.T) {
	repo, _, _ := newRedisVaultRepo(t)
	store, ok := repo.(domain.ProviderPrefixStore)
	if !ok {
		t.Fatal("redis vault does not implement ProviderPrefixStore")
	}
	ctx := context.Background()
	gw, other := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	const prefix = "uhdr:reg-1:"
	for _, c := range []*domain.Credential{
		newTestCredential(t, gw, "ana", prefix+"X-Api-Key", "a", ""),
		newTestCredential(t, gw, "app:c1:bruno", prefix+"X-Api-Key", "b", ""),
		newTestCredential(t, gw, "ana", "uhdr:reg-10:X-Api-Key", "c", ""),
		newTestCredential(t, gw, "ana", "com.linear/mcp|abcd", "d", "r"),
		newTestCredential(t, other, "ana", prefix+"X-Api-Key", "e", ""),
	} {
		if err := repo.Upsert(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	list, err := store.ListByProviderPrefix(ctx, gw, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].PrincipalSub != "ana" || list[1].PrincipalSub != "app:c1:bruno" {
		t.Fatalf("list = %+v, want ana and app:c1:bruno only", list)
	}
	n, err := store.DeleteByProviderPrefix(ctx, gw, prefix)
	if err != nil || n != 2 {
		t.Fatalf("deleted %d, err %v; want 2", n, err)
	}
	if _, err := repo.Find(ctx, gw, "ana", "uhdr:reg-10:X-Api-Key"); err != nil {
		t.Fatalf("a sibling registry's value was deleted: %v", err)
	}
	if _, err := repo.Find(ctx, other, "ana", prefix+"X-Api-Key"); err != nil {
		t.Fatalf("another gateway's value was deleted: %v", err)
	}
	if _, err := store.ListByProviderPrefix(ctx, gw, ""); err == nil {
		t.Fatal("an empty prefix must be refused")
	}
}

func TestFallbackRepository_ReplicatedWriteReachesBothStores(t *testing.T) {
	primary, _, _ := newRedisVaultRepo(t)
	secondary, _, _ := newRedisVaultRepo(t)
	repo := vaultrepo.NewFallbackRepository(primary, secondary)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()
	writer, ok := repo.(domain.ReplicatedUpserter)
	if !ok {
		t.Fatal("fallback vault does not implement ReplicatedUpserter")
	}
	if err := writer.UpsertReplicated(ctx, newTestCredential(t, gw, "ana", "uhdr:r:X-Api-Key", "v", "")); err != nil {
		t.Fatal(err)
	}
	for name, store := range map[string]domain.Repository{"primary": primary, "secondary": secondary} {
		if _, err := store.Find(ctx, gw, "ana", "uhdr:r:X-Api-Key"); err != nil {
			t.Fatalf("%s does not hold the value: %v", name, err)
		}
	}
	lister := repo.(domain.ProviderPrefixStore)
	list, err := lister.ListByProviderPrefix(ctx, gw, "uhdr:r:")
	if err != nil || len(list) != 1 {
		t.Fatalf("merged list = %+v err %v; want one entry", list, err)
	}
	if n, err := lister.DeleteByProviderPrefix(ctx, gw, "uhdr:r:"); err != nil || n != 1 {
		t.Fatalf("deleted %d err %v", n, err)
	}
	if _, err := secondary.Find(ctx, gw, "ana", "uhdr:r:X-Api-Key"); err == nil {
		t.Fatal("reset left a live copy on the data plane store")
	}
}
