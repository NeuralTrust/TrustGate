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
	vaultrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/vault"
)

func TestRedisRepository_ExistsBoundMatchesCodeNotSibling(t *testing.T) {
	repo, _, _ := newRedisVaultRepo(t)
	checker, ok := repo.(interface {
		ExistsBound(context.Context, ids.GatewayID, string) (bool, error)
	})
	if !ok {
		t.Fatal("redis vault does not implement ExistsBound")
	}
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()
	const code = "com.vercel/mcp"
	if err := repo.Upsert(ctx, newTestCredential(t, gw, "user-1", code+"2|abcd", "a", "r")); err != nil {
		t.Fatal(err)
	}
	found, err := checker.ExistsBound(ctx, gw, code)
	if err != nil || found {
		t.Fatalf("sibling code matched: found=%v err=%v", found, err)
	}
	if err := repo.Upsert(ctx, newTestCredential(t, gw, "user-2", code+"|abcd", "a", "r")); err != nil {
		t.Fatal(err)
	}
	found, err = checker.ExistsBound(ctx, gw, code)
	if err != nil || !found {
		t.Fatalf("fingerprinted provider not found: found=%v err=%v", found, err)
	}
}

func TestFallbackRepository_ExistsBoundOrsStores(t *testing.T) {
	primary, _, _ := newRedisVaultRepo(t)
	secondary, _, _ := newRedisVaultRepo(t)
	repo := vaultrepo.NewFallbackRepository(primary, secondary)
	checker, ok := repo.(interface {
		ExistsBound(context.Context, ids.GatewayID, string) (bool, error)
	})
	if !ok {
		t.Fatal("fallback vault does not implement ExistsBound")
	}
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()
	const code = "dev.firecrawl/mcp"
	found, err := checker.ExistsBound(ctx, gw, code)
	if err != nil || found {
		t.Fatalf("empty stores: found=%v err=%v", found, err)
	}
	if err := secondary.Upsert(ctx, newTestCredential(t, gw, "user-1", "urlvar:"+code+":token", "a", "r")); err != nil {
		t.Fatal(err)
	}
	found, err = checker.ExistsBound(ctx, gw, code)
	if err != nil || !found {
		t.Fatalf("fallback credential missed: found=%v err=%v", found, err)
	}
}
