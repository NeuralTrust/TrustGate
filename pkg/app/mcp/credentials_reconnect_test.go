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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

// reconnectVault is memVault plus the conditional mark the real stores
// implement. It hands out copies, as a real store does, so a credential read
// before a rewrite really is stale.
type reconnectVault struct {
	*memVault
}

func (v reconnectVault) Upsert(ctx context.Context, c *vaultdomain.Credential) error {
	stored := *c
	stored.UpdatedAt = time.Now()
	return v.memVault.Upsert(ctx, &stored)
}

func (v reconnectVault) Find(ctx context.Context, gw ids.GatewayID, sub, provider string) (*vaultdomain.Credential, error) {
	stored, err := v.memVault.Find(ctx, gw, sub, provider)
	if err != nil {
		return nil, err
	}
	out := *stored
	return &out, nil
}

func (v reconnectVault) RequireReconnect(_ context.Context, c *vaultdomain.Credential) error {
	key := v.key(c.GatewayID, c.PrincipalSub, c.Provider)
	stored, ok := v.creds[key]
	if !ok || !stored.UpdatedAt.Equal(c.UpdatedAt) {
		return vaultdomain.ErrCredentialChanged
	}
	marked := *stored
	now := time.Now()
	marked.RefreshToken = ""
	marked.ExpiresAt, marked.UpdatedAt = now, now
	v.creds[key] = &marked
	return nil
}

// RUN-1764: Linear refused a grant and every replica's connect page kept saying
// "Connected", because the refusal lived only in the memory of the replica that
// saw it while the dead refresh token stayed in the shared vault.
func TestCredentialResolver_DefinitiveRefreshFailureRequiresReconnect(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg := regWithAuth(gw, &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeForwarded, Provider: "linear", ClientID: "id",
		AuthorizeURL: "https://l/a", TokenURL: "https://l/t",
	})
	vaultProvider := registrydomain.ForwardedVaultProvider(reg)

	idp := func(t *testing.T, requests *atomic.Int64, status int, body map[string]any, before ...func()) string {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			for _, hook := range before {
				hook()
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	resolver := func(t *testing.T, vault vaultdomain.Repository, connect *stubConnect) *credentialResolver {
		t.Helper()
		r, ok := NewCredentialResolver(nil, vault, connect, infraoauth.NewProviderClient(nil), discardLogger()).(*credentialResolver)
		if !ok {
			t.Fatal("NewCredentialResolver did not return *credentialResolver")
		}
		return r
	}
	seed := func(t *testing.T, sub string) reconnectVault {
		t.Helper()
		vault := reconnectVault{&memVault{}}
		cred, err := vaultdomain.NewCredential(gw, sub, vaultProvider, "acct-"+sub, "old", "dead-refresh", nil, time.Now().Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		_ = vault.Upsert(context.Background(), cred)
		return vault
	}
	// The predicate the connect page, the Portal and the shared-account view
	// all apply to decide between "Connected" and "Reconnect".
	needsReconnect := func(t *testing.T, vault reconnectVault, sub string) bool {
		t.Helper()
		stored, err := vault.Find(context.Background(), gw, sub, vaultProvider)
		if err != nil {
			t.Fatalf("find: %v", err)
		}
		if stored.AccountRef != "acct-"+sub {
			t.Fatalf("the account was lost: %+v", stored)
		}
		return stored.RefreshToken == "" && stored.Expired(time.Minute)
	}
	apply := func(t *testing.T, r *credentialResolver, sub string) *ConsentRequiredError {
		t.Helper()
		target := Target{}
		err := r.Apply(principalCtx(&identity.Principal{Subject: sub}), mcpConsumer(gw), reg, &target)
		var consent *ConsentRequiredError
		if !errors.As(err, &consent) {
			t.Fatalf("Apply error = %v, want consent", err)
		}
		if target.Headers["Authorization"] != "" {
			t.Fatal("a refused credential was injected")
		}
		return consent
	}

	t.Run("a rejected refresh token marks the account for every replica", func(t *testing.T) {
		t.Parallel()
		var requests atomic.Int64
		url := idp(t, &requests, http.StatusBadRequest, map[string]any{
			"error": "invalid_grant", "error_description": "Grant not found",
		})
		vault := seed(t, "alice")
		connect := &stubConnect{ticket: "reconnect", refreshCfg: &registrydomain.MCPAuth{Provider: "linear", ClientID: "dcr", TokenURL: url}}

		if consent := apply(t, resolver(t, vault, connect), "alice"); consent.Cause != ConsentCauseRefreshRejected {
			t.Fatalf("cause = %q, want %q", consent.Cause, ConsentCauseRefreshRejected)
		}
		if !needsReconnect(t, vault, "alice") {
			t.Fatal("the vault still reads as connected after the provider refused the grant")
		}
		// Another replica holds no in-memory marker and must not replay the grant.
		if consent := apply(t, resolver(t, vault, connect), "alice"); consent.Ticket != "reconnect" {
			t.Fatalf("ticket = %q, want a connect link", consent.Ticket)
		}
		if got := requests.Load(); got != 1 {
			t.Fatalf("token endpoint requests = %d, want 1", got)
		}
	})

	// The retry after an upstream 401 hands back the access token it sent; a
	// marked credential must still end in consent, never in an empty bearer.
	t.Run("a call rejected upstream after the mark asks for consent", func(t *testing.T) {
		t.Parallel()
		var requests atomic.Int64
		url := idp(t, &requests, http.StatusBadRequest, map[string]any{
			"error": "invalid_grant", "error_description": "Grant not found",
		})
		vault := seed(t, "dave")
		connect := &stubConnect{ticket: "reconnect", refreshCfg: &registrydomain.MCPAuth{Provider: "linear", ClientID: "dcr", TokenURL: url}}
		_ = apply(t, resolver(t, vault, connect), "dave")

		target := Target{Headers: map[string]string{"Authorization": "Bearer old"}}
		err := resolver(t, vault, connect).Refresh(principalCtx(&identity.Principal{Subject: "dave"}), mcpConsumer(gw), reg, &target)
		var consent *ConsentRequiredError
		if !errors.As(err, &consent) {
			t.Fatalf("Refresh error = %v, want consent", err)
		}
		if got := target.Headers["Authorization"]; got != "Bearer old" {
			t.Fatalf("Authorization = %q, want the rejected token left untouched", got)
		}
		if got := requests.Load(); got != 1 {
			t.Fatalf("token endpoint requests = %d, want 1", got)
		}
	})

	t.Run("a reconnect that lands before the mark survives it", func(t *testing.T) {
		t.Parallel()
		var requests atomic.Int64
		vault := seed(t, "erin")
		// Expired on arrival so the peer-rotation re-read does not short-circuit
		// the mark: this is the conditional write's own guard.
		reconnect := func() {
			cred, _ := vaultdomain.NewCredential(gw, "erin", vaultProvider, "acct-erin", "new", "fresh-refresh", nil, time.Now().Add(-time.Minute))
			_ = vault.Upsert(context.Background(), cred)
		}
		url := idp(t, &requests, http.StatusBadRequest, map[string]any{
			"error": "invalid_grant", "error_description": "Grant not found",
		}, reconnect)
		connect := &stubConnect{ticket: "reconnect", refreshCfg: &registrydomain.MCPAuth{Provider: "linear", ClientID: "dcr", TokenURL: url}}
		_ = apply(t, resolver(t, vault, connect), "erin")

		stored, err := vault.Find(context.Background(), gw, "erin", vaultProvider)
		if err != nil {
			t.Fatal(err)
		}
		if stored.RefreshToken != "fresh-refresh" {
			t.Fatalf("the mark wiped a newer reconnect: %+v", stored)
		}
	})

	t.Run("a lost registered client marks the account", func(t *testing.T) {
		t.Parallel()
		vault := seed(t, "bob")
		connect := &stubConnect{ticket: "reconnect", refreshErr: fmt.Errorf("%w: provider %q", appoauth.ErrNoRegisteredClient, "linear")}

		if consent := apply(t, resolver(t, vault, connect), "bob"); consent.Cause != ConsentCauseRegisteredClientLost {
			t.Fatalf("cause = %q, want %q", consent.Cause, ConsentCauseRegisteredClientLost)
		}
		if !needsReconnect(t, vault, "bob") {
			t.Fatal("the vault still reads as connected after the registered client was lost")
		}
	})

	t.Run("a transient provider failure leaves the account alone", func(t *testing.T) {
		t.Parallel()
		var requests atomic.Int64
		url := idp(t, &requests, http.StatusServiceUnavailable, map[string]any{"error": "temporarily_unavailable"})
		vault := seed(t, "carol")
		connect := &stubConnect{ticket: "reconnect", refreshCfg: &registrydomain.MCPAuth{Provider: "linear", ClientID: "dcr", TokenURL: url}}

		target := Target{}
		err := resolver(t, vault, connect).Apply(principalCtx(&identity.Principal{Subject: "carol"}), mcpConsumer(gw), reg, &target)
		if err == nil {
			t.Fatal("Apply must fail while the provider is down")
		}
		stored, findErr := vault.Find(context.Background(), gw, "carol", vaultProvider)
		if findErr != nil {
			t.Fatal(findErr)
		}
		if stored.RefreshToken != "dead-refresh" {
			t.Fatalf("a transient failure dropped the refresh token: %+v", stored)
		}
	})
}
