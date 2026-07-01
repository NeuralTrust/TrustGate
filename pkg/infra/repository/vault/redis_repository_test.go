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
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	vaultrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/vault"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
)

func newRedisVaultRepo(t *testing.T) (vaultdomain.Repository, *miniredis.Miniredis, vaultdomain.Encrypter) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	cipher, err := crypto.NewCipher("test-secret-key-that-is-long-enough-1234567890")
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	return vaultrepo.NewRedisRepository(rdb, cipher), mr, cipher
}

func newTestCredential(t *testing.T, gw ids.GatewayID, sub, provider, access, refresh string) *vaultdomain.Credential {
	t.Helper()
	cred, err := vaultdomain.NewCredential(gw, sub, provider, "acct-"+provider, access, refresh, []string{"read"}, time.Now().Add(time.Hour).UTC())
	if err != nil {
		t.Fatalf("new credential: %v", err)
	}
	return cred
}

func TestRedisRepository_UpsertFindRoundTrip(t *testing.T) {
	repo, _, _ := newRedisVaultRepo(t)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()

	cred := newTestCredential(t, gw, "user-1", "github", "access-token", "refresh-token")
	if err := repo.Upsert(ctx, cred); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := repo.Find(ctx, gw, "user-1", "github")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.AccessToken != "access-token" || got.RefreshToken != "refresh-token" {
		t.Fatalf("token mismatch: %+v", got)
	}
	if got.AccountRef != "acct-github" || got.Provider != "github" || got.PrincipalSub != "user-1" {
		t.Fatalf("metadata mismatch: %+v", got)
	}
	if got.GatewayID != gw {
		t.Fatalf("gateway id mismatch: %v != %v", got.GatewayID, gw)
	}
}

func TestRedisRepository_StoresEncryptedBlob(t *testing.T) {
	repo, mr, cipher := newRedisVaultRepo(t)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()

	cred := newTestCredential(t, gw, "user-1", "github", "plaintext-access", "plaintext-refresh")
	if err := repo.Upsert(ctx, cred); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	key := "vault:" + gw.String() + ":user-1:github"
	raw, err := mr.Get(key)
	if err != nil {
		t.Fatalf("miniredis get: %v", err)
	}
	if strings.Contains(raw, "plaintext-access") || strings.Contains(raw, "plaintext-refresh") {
		t.Fatalf("raw redis value leaked plaintext tokens: %s", raw)
	}

	var blob struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(raw), &blob); err != nil {
		t.Fatalf("unmarshal raw blob: %v", err)
	}
	if blob.AccessToken == "plaintext-access" {
		t.Fatal("access token stored as plaintext")
	}
	access, err := cipher.Decrypt(blob.AccessToken)
	if err != nil {
		t.Fatalf("decrypt stored access token: %v", err)
	}
	if access != "plaintext-access" {
		t.Fatalf("decrypted access token = %q, want %q", access, "plaintext-access")
	}
	refresh, err := cipher.Decrypt(blob.RefreshToken)
	if err != nil {
		t.Fatalf("decrypt stored refresh token: %v", err)
	}
	if refresh != "plaintext-refresh" {
		t.Fatalf("decrypted refresh token = %q, want %q", refresh, "plaintext-refresh")
	}
}

func TestRedisRepository_UpsertPreservesRefreshWhenEmpty(t *testing.T) {
	repo, _, _ := newRedisVaultRepo(t)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()

	if err := repo.Upsert(ctx, newTestCredential(t, gw, "user-1", "github", "access-1", "refresh-1")); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	refreshed := newTestCredential(t, gw, "user-1", "github", "access-2", "")
	if err := repo.Upsert(ctx, refreshed); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, err := repo.Find(ctx, gw, "user-1", "github")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.AccessToken != "access-2" {
		t.Fatalf("access token = %q, want access-2", got.AccessToken)
	}
	if got.RefreshToken != "refresh-1" {
		t.Fatalf("refresh token = %q, want preserved refresh-1", got.RefreshToken)
	}
}

func TestRedisRepository_ListByPrincipal(t *testing.T) {
	repo, _, _ := newRedisVaultRepo(t)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()
	other := ids.New[ids.GatewayKind]()

	if err := repo.Upsert(ctx, newTestCredential(t, gw, "user-1", "github", "a", "r")); err != nil {
		t.Fatalf("upsert github: %v", err)
	}
	if err := repo.Upsert(ctx, newTestCredential(t, gw, "user-1", "atlassian", "a", "r")); err != nil {
		t.Fatalf("upsert atlassian: %v", err)
	}
	if err := repo.Upsert(ctx, newTestCredential(t, gw, "user-2", "github", "a", "r")); err != nil {
		t.Fatalf("upsert other principal: %v", err)
	}
	if err := repo.Upsert(ctx, newTestCredential(t, other, "user-1", "github", "a", "r")); err != nil {
		t.Fatalf("upsert other gateway: %v", err)
	}

	creds, err := repo.ListByPrincipal(ctx, gw, "user-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials for principal, got %d", len(creds))
	}
	if creds[0].Provider != "atlassian" || creds[1].Provider != "github" {
		t.Fatalf("providers not sorted: %s, %s", creds[0].Provider, creds[1].Provider)
	}
}

func TestRedisRepository_ListByPrincipalIsolatesGlobAndDelimiterSubjects(t *testing.T) {
	repo, _, _ := newRedisVaultRepo(t)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()

	if err := repo.Upsert(ctx, newTestCredential(t, gw, "user:1", "github", "a", "r")); err != nil {
		t.Fatalf("upsert delimiter sub: %v", err)
	}
	if err := repo.Upsert(ctx, newTestCredential(t, gw, "user:1:extra", "github", "a", "r")); err != nil {
		t.Fatalf("upsert nested sub: %v", err)
	}
	if err := repo.Upsert(ctx, newTestCredential(t, gw, "*", "github", "a", "r")); err != nil {
		t.Fatalf("upsert glob sub: %v", err)
	}

	creds, err := repo.ListByPrincipal(ctx, gw, "user:1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected exactly 1 credential for principal user:1, got %d", len(creds))
	}
	if creds[0].PrincipalSub != "user:1" {
		t.Fatalf("leaked another principal: %s", creds[0].PrincipalSub)
	}

	globCreds, err := repo.ListByPrincipal(ctx, gw, "*")
	if err != nil {
		t.Fatalf("list glob principal: %v", err)
	}
	if len(globCreds) != 1 || globCreds[0].PrincipalSub != "*" {
		t.Fatalf("glob principal must not match every key, got %d", len(globCreds))
	}
}

func TestRedisRepository_Delete(t *testing.T) {
	repo, _, _ := newRedisVaultRepo(t)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()

	if err := repo.Upsert(ctx, newTestCredential(t, gw, "user-1", "github", "a", "r")); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := repo.Delete(ctx, gw, "user-1", "github"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.Find(ctx, gw, "user-1", "github"); !errors.Is(err, vaultdomain.ErrNotFound) {
		t.Fatalf("find after delete err = %v, want ErrNotFound", err)
	}
	if err := repo.Delete(ctx, gw, "user-1", "github"); !errors.Is(err, vaultdomain.ErrNotFound) {
		t.Fatalf("delete missing err = %v, want ErrNotFound", err)
	}
}

func TestRedisRepository_FindMissingReturnsNotFound(t *testing.T) {
	repo, _, _ := newRedisVaultRepo(t)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()

	_, err := repo.Find(ctx, gw, "nobody", "github")
	if !errors.Is(err, vaultdomain.ErrNotFound) {
		t.Fatalf("find missing err = %v, want ErrNotFound", err)
	}
}
