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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

// Google answered 401 on Gmail, Drive and Calendar to tokens it had just
// refreshed. The gateway logged each one, hid the servers as unreachable, and
// trustgate_access refused a connect link: "connecting would not change
// that". A token refused right after a refresh is a grant the server no
// longer accepts, and a new authorization is what replaces it.
func TestCredentialResolver_ACredentialRejectedAfterRefreshAsksToReconnect(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg := regWithAuth(gw, &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeForwarded, Provider: "com.google.workspace/gmail", ClientID: "id",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token",
	})
	vaultProvider := registrydomain.ForwardedVaultProvider(reg)
	vault := reconnectVault{&memVault{}}
	cred, err := vaultdomain.NewCredential(gw, "ana", vaultProvider, "ana@acme.test", "fresh", "refresh", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_ = vault.Upsert(context.Background(), cred)
	r, ok := NewCredentialResolver(nil, vault, &stubConnect{ticket: "reconnect"}, infraoauth.NewProviderClient(nil), discardLogger()).(*credentialResolver)
	if !ok {
		t.Fatal("NewCredentialResolver did not return *credentialResolver")
	}
	ctx := principalCtx(&identity.Principal{Subject: "ana"})

	err = r.RejectRefreshed(ctx, mcpConsumer(gw), reg)
	var consent *ConsentRequiredError
	if !errors.As(err, &consent) || consent.Cause != ConsentCauseCredentialRejected || consent.Ticket != "reconnect" {
		t.Fatalf("RejectRefreshed = %v, want a connect link with cause %q", err, ConsentCauseCredentialRejected)
	}

	// Every replica, and the Store's own status, now read it as waiting on the
	// person: the next call asks to connect instead of dialing with it.
	stored, _ := vault.Find(context.Background(), gw, "ana", vaultProvider)
	if stored.RefreshToken != "" || !stored.Expired(time.Minute) || stored.AccountRef != "ana@acme.test" {
		t.Fatalf("stored credential = %+v, want it marked for a reconnect with its account kept", stored)
	}
	target := Target{}
	if err := r.Apply(ctx, mcpConsumer(gw), reg, &target); !errors.As(err, &consent) {
		t.Fatalf("Apply after the rejection = %v, want consent", err)
	}
}

// Only a person's own OAuth account is theirs to reconnect. A credential an
// administrator configured stays the upstream's rejection.
func TestCredentialResolver_ACredentialNobodyReconnectsStaysRejected(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	r, ok := NewCredentialResolver(nil, reconnectVault{&memVault{}}, &stubConnect{ticket: "reconnect"}, infraoauth.NewProviderClient(nil), discardLogger()).(*credentialResolver)
	if !ok {
		t.Fatal("NewCredentialResolver did not return *credentialResolver")
	}
	static := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, MCPTarget: &registrydomain.MCPTarget{
		URL: "https://up.example.com/mcp", Auth: &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic, Value: "key"},
	}}
	if err := r.RejectRefreshed(principalCtx(&identity.Principal{Subject: "ana"}), mcpConsumer(gw), static); err != nil {
		t.Fatalf("static credential: %v, want nil", err)
	}
	forwarded := regWithAuth(gw, &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: "linear", ClientID: "id"})
	if err := r.RejectRefreshed(context.Background(), mcpConsumer(gw), forwarded); err != nil {
		t.Fatalf("no principal: %v, want nil", err)
	}
}

// rejectingCreds refreshes on demand and turns a refused refreshed token into
// the reconnect the resolver would ask for.
type rejectingCreds struct {
	reactiveCreds
	refreshErr error
	rejected   atomic.Int64
}

func (c *rejectingCreds) Refresh(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, target *Target) error {
	if c.refreshErr != nil {
		c.refreshes.Add(1)
		return c.refreshErr
	}
	return c.reactiveCreds.Refresh(ctx, rc, reg, target)
}

func (c *rejectingCreds) RejectRefreshed(context.Context, *appconsumer.RoutableConsumer, *registrydomain.Registry) error {
	c.rejected.Add(1)
	return &ConsentRequiredError{Provider: "gmail", Ticket: "reconnect", Cause: ConsentCauseCredentialRejected}
}

func TestInvokeUpstream_ARefreshedTokenRefusedAgainBecomesAReconnect(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "gmail", "https://gmailmcp.googleapis.com/mcp/v1")
	refuse := DialerFunc(func(context.Context, Target) (Upstream, error) { return nil, ErrUpstreamUnauthorized })
	list := func(up Upstream) ([]Tool, error) { return up.ListTools(context.Background()) }

	t.Run("refused after a refresh", func(t *testing.T) {
		t.Parallel()
		creds := &rejectingCreds{}
		_, err := invokeUpstream(&composer{dialer: refuse, creds: creds}, context.Background(), nil, reg, list)
		var consent *ConsentRequiredError
		if !errors.As(err, &consent) || consent.Cause != ConsentCauseCredentialRejected {
			t.Fatalf("error = %v, want the reconnect", err)
		}
		if creds.refreshes.Load() != 1 || creds.rejected.Load() != 1 {
			t.Fatalf("refreshes = %d, rejections = %d, want 1 each", creds.refreshes.Load(), creds.rejected.Load())
		}
	})
	t.Run("refused within the refresh cooldown", func(t *testing.T) {
		t.Parallel()
		creds := &rejectingCreds{refreshErr: errCredentialRefreshThrottled}
		_, err := invokeUpstream(&composer{dialer: refuse, creds: creds}, context.Background(), nil, reg, list)
		var consent *ConsentRequiredError
		if !errors.As(err, &consent) {
			t.Fatalf("error = %v, want the reconnect", err)
		}
	})
	t.Run("a credential that cannot refresh stays rejected", func(t *testing.T) {
		t.Parallel()
		creds := &rejectingCreds{refreshErr: errCredentialRefreshUnsupported}
		_, err := invokeUpstream(&composer{dialer: refuse, creds: creds}, context.Background(), nil, reg, list)
		if !errors.Is(err, ErrUpstreamUnauthorized) || creds.rejected.Load() != 0 {
			t.Fatalf("error = %v (rejections %d), want the upstream's 401", err, creds.rejected.Load())
		}
	})
}

// A refresh the provider refuses because of the client itself (a stale or
// mistyped secret on the server) is the administrator's to fix: the error
// names the server and who acts, and the inventory says so.
func TestCredentialResolver_ARejectedOAuthClientNamesWhoFixesIt(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client", "error_description": "The provided client secret is invalid."})
	}))
	t.Cleanup(idp.Close)

	run := func(t *testing.T, registration registrydomain.MCPClientRegistration) error {
		t.Helper()
		auth := &registrydomain.MCPAuth{
			Mode: registrydomain.MCPAuthModeForwarded, Provider: "com.google.workspace/gmail", ClientID: "id",
			AuthorizeURL: "https://accounts.google.com/a", TokenURL: idp.URL,
		}
		if registration == registrydomain.RegistrationAuto {
			auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: "com.google.workspace/gmail", Registration: registration}
		}
		reg := regWithAuth(gw, auth)
		reg.Name = "Gmail"
		vault := reconnectVault{&memVault{}}
		cred, err := vaultdomain.NewCredential(gw, "ana", registrydomain.ForwardedVaultProvider(reg), "ana@acme.test", "old", "refresh", nil, time.Now().Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		_ = vault.Upsert(context.Background(), cred)
		connect := &stubConnect{ticket: "reconnect", refreshCfg: &registrydomain.MCPAuth{Provider: "com.google.workspace/gmail", ClientID: "id", ClientSecret: "stale", TokenURL: idp.URL}}
		r, ok := NewCredentialResolver(nil, vault, connect, infraoauth.NewProviderClient(nil), discardLogger()).(*credentialResolver)
		if !ok {
			t.Fatal("NewCredentialResolver did not return *credentialResolver")
		}
		return r.Apply(principalCtx(&identity.Principal{Subject: "ana"}), mcpConsumer(gw), reg, &Target{})
	}

	err := run(t, "")
	var rejected *OAuthClientRejectedError
	if !errors.As(err, &rejected) || rejected.Code != "invalid_client" || !errors.Is(err, appoauth.ErrInvalidClient) {
		t.Fatalf("Apply = %v, want the server's OAuth client named as rejected", err)
	}
	if text := err.Error(); !strings.Contains(text, "Gmail") || !strings.Contains(text, "administrator") || strings.Contains(text, "stale") {
		t.Fatalf("message = %q", text)
	}
	if got := inventoryCauseForFailure(err); got != InventoryCauseOAuthClientRejected {
		t.Fatalf("inventory cause = %q, want %q", got, InventoryCauseOAuthClientRejected)
	}
	if got := callerSafeText("gmail_search", err); got != err.Error() {
		t.Fatalf("a program is told %q, want the same words", got)
	}

	// A dynamically registered client is dropped and registered again on the
	// next connect: not the administrator's to fix.
	if err := run(t, registrydomain.RegistrationAuto); errors.As(err, &rejected) {
		t.Fatalf("a dynamic client was reported as the administrator's: %v", err)
	}
}

func TestUnavailableConnectAnswer_SaysWhoCanChangeIt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		cause, wantError, wantText string
	}{
		{InventoryCauseOAuthClientRejected, "oauth_client_rejected", "client ID or secret"},
		{"credential_rejected_401", "credential_rejected", "an administrator updates it"},
		{"timeout", "unavailable", "Connecting would not change that"},
	} {
		raw, err := unavailableConnectAnswer(InventoryServer{Name: "Gmail", State: InventoryStateUnavailable, Cause: tc.cause})
		if err != nil {
			t.Fatal(err)
		}
		var answer struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			Structured map[string]any `json:"structuredContent"`
			IsError    bool           `json:"isError"`
		}
		if err := json.Unmarshal(raw, &answer); err != nil {
			t.Fatal(err)
		}
		if !answer.IsError || answer.Structured["error"] != tc.wantError || !strings.Contains(answer.Content[0].Text, tc.wantText) {
			t.Errorf("%s: answer = %+v", tc.cause, answer)
		}
	}
}
