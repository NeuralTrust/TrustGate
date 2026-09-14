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

package mcp

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	vaultrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/vault"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type refreshProviderFunc struct {
	appoauth.ProviderClient
	refresh func(context.Context) (*appoauth.ProviderToken, error)
}

func (p refreshProviderFunc) Refresh(ctx context.Context, _ *registrydomain.MCPAuth, _ string) (*appoauth.ProviderToken, error) {
	return p.refresh(ctx)
}

type observedRefreshVault struct {
	vaultdomain.Repository
	credentialRefreshLocker
	acquire chan struct{}
	persist func(context.Context, *vaultdomain.Credential) error
}

func (v *observedRefreshVault) AcquireRefreshLock(ctx context.Context, gw ids.GatewayID, subject, provider string) (func(context.Context) error, error) {
	if v.acquire != nil {
		close(v.acquire)
	}
	return v.credentialRefreshLocker.AcquireRefreshLock(ctx, gw, subject, provider)
}
func (v *observedRefreshVault) Upsert(ctx context.Context, cred *vaultdomain.Credential) error {
	if v.persist != nil {
		return v.persist(ctx, cred)
	}
	return v.Repository.Upsert(ctx, cred)
}

func refreshRedisVault(t *testing.T, mr *miniredis.Miniredis) vaultdomain.Repository {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	cipher, err := crypto.NewCipher("refresh-test-encryption-secret-long-enough")
	require.NoError(t, err)
	return vaultrepo.NewRedisRepository(client, cipher)
}

func TestCredentialRefreshSerializesAcrossResolvers(t *testing.T) {
	mr := miniredis.RunT(t)
	firstVault, secondVault := refreshRedisVault(t, mr), refreshRedisVault(t, mr)
	gw := ids.New[ids.GatewayKind]()
	reg := regWithAuth(gw, &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: "provider", Registration: registrydomain.RegistrationAuto})
	cred, err := vaultdomain.NewCredential(gw, "alice", registrydomain.ForwardedVaultProvider(reg), "", "old", "old-refresh", nil, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	require.NoError(t, firstVault.Upsert(context.Background(), cred))
	started, release, waiting := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	provider := refreshProviderFunc{refresh: func(ctx context.Context) (*appoauth.ProviderToken, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
		}
		return &appoauth.ProviderToken{AccessToken: "fresh", RefreshToken: "fresh-refresh", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}}
	second := &observedRefreshVault{Repository: secondVault, credentialRefreshLocker: secondVault.(credentialRefreshLocker), acquire: waiting}
	connect := &stubConnect{}
	resolvers := []CredentialResolver{NewCredentialResolver(nil, firstVault, connect, provider, discardLogger()), NewCredentialResolver(nil, second, connect, provider, discardLogger())}
	results := make(chan error, 2)
	run := func(r CredentialResolver) {
		target := Target{}
		err := r.Apply(principalCtx(&identity.Principal{Subject: "alice"}), mcpConsumer(gw), reg, &target)
		if err == nil && target.Headers["Authorization"] != "Bearer fresh" {
			err = errors.New("refreshed token was not reused")
		}
		results <- err
	}
	go run(resolvers[0])
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not start")
	}
	go run(resolvers[1])
	select {
	case <-waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("peer did not attempt distributed lock")
	}
	close(release)
	for range 2 {
		select {
		case err := <-results:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("refresh did not finish")
		}
	}
	require.EqualValues(t, 1, calls.Load())
	stored, err := secondVault.Find(context.Background(), gw, "alice", cred.Provider)
	require.NoError(t, err)
	require.Equal(t, "fresh-refresh", stored.RefreshToken)
}

func TestCredentialRefreshPersistsAfterCallerCancellation(t *testing.T) {
	mr := miniredis.RunT(t)
	base := refreshRedisVault(t, mr)
	gw := ids.New[ids.GatewayKind]()
	reg := regWithAuth(gw, &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: "provider", Registration: registrydomain.RegistrationAuto})
	cred, err := vaultdomain.NewCredential(gw, "alice", registrydomain.ForwardedVaultProvider(reg), "", "old", "old-refresh", nil, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	require.NoError(t, base.Upsert(context.Background(), cred))
	ctx, cancel := context.WithCancel(principalCtx(&identity.Principal{Subject: "alice"}))
	defer cancel()
	persisted := make(chan error, 1)
	vault := &observedRefreshVault{Repository: base, credentialRefreshLocker: base.(credentialRefreshLocker)}
	vault.persist = func(persistCtx context.Context, c *vaultdomain.Credential) error {
		cancel()
		if _, ok := persistCtx.Deadline(); !ok {
			persisted <- errors.New("persistence has no deadline")
			return errors.New("missing deadline")
		}
		err := base.Upsert(persistCtx, c)
		persisted <- err
		return err
	}
	provider := refreshProviderFunc{refresh: func(context.Context) (*appoauth.ProviderToken, error) {
		return &appoauth.ProviderToken{AccessToken: "fresh", RefreshToken: "rotated", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}}
	resolver := NewCredentialResolver(nil, vault, &stubConnect{}, provider, discardLogger())
	err = resolver.Apply(ctx, mcpConsumer(gw), reg, &Target{})
	require.True(t, err == nil || errors.Is(err, context.Canceled))
	select {
	case err := <-persisted:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("rotation was not persisted")
	}
	stored, err := base.Find(context.Background(), gw, "alice", cred.Provider)
	require.NoError(t, err)
	require.Equal(t, "rotated", stored.RefreshToken)
	lockCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	unlock, err := base.(credentialRefreshLocker).AcquireRefreshLock(lockCtx, gw, "alice", cred.Provider)
	require.NoError(t, err)
	require.NoError(t, unlock(lockCtx))
}

func TestCredentialRefreshWaiterCanCancel(t *testing.T) {
	mr := miniredis.RunT(t)
	vault := refreshRedisVault(t, mr)
	gw := ids.New[ids.GatewayKind]()
	reg := regWithAuth(gw, &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: "provider", Registration: registrydomain.RegistrationAuto})
	cred, err := vaultdomain.NewCredential(gw, "alice", registrydomain.ForwardedVaultProvider(reg), "", "old", "old-refresh", nil, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	require.NoError(t, vault.Upsert(context.Background(), cred))
	started, release := make(chan struct{}), make(chan struct{})
	provider := refreshProviderFunc{refresh: func(ctx context.Context) (*appoauth.ProviderToken, error) {
		close(started)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
		}
		return &appoauth.ProviderToken{AccessToken: "fresh", RefreshToken: "rotated", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}}
	resolver := NewCredentialResolver(nil, vault, &stubConnect{}, provider, discardLogger()).(*credentialResolver)
	done := make(chan error, 1)
	go func() {
		done <- resolver.Apply(principalCtx(&identity.Principal{Subject: "alice"}), mcpConsumer(gw), reg, &Target{})
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not start")
	}
	waiterCtx, cancel := context.WithTimeout(principalCtx(&identity.Principal{Subject: "alice"}), 30*time.Millisecond)
	defer cancel()
	err = resolver.Apply(waiterCtx, mcpConsumer(gw), reg, &Target{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	close(release)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not complete")
	}
}
