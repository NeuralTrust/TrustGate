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
	"strings"
	"testing"
	"time"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// userHeaderVault is a memVault that can mark a credential refused, as the
// Postgres and Redis vaults do.
type userHeaderVault struct{ *memVault }

func (v userHeaderVault) RequireReconnect(_ context.Context, c *vaultdomain.Credential) error {
	stored := v.creds[v.key(c.GatewayID, c.PrincipalSub, c.Provider)]
	if stored == nil {
		return vaultdomain.ErrCredentialChanged
	}
	stored.ExpiresAt = time.Now().Add(-time.Second)
	return nil
}

func regWithUserHeaders(gw ids.GatewayID, headers ...registrydomain.MCPUserHeader) *registrydomain.Registry {
	reg, err := registrydomain.NewMCPRegistry(gw, "keyed", "", &registrydomain.MCPTarget{
		URL:         "https://keyed.example.com/mcp",
		Auth:        &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeNone},
		Headers:     map[string]string{"X-Tenant": "acme"},
		UserHeaders: headers,
	})
	if err != nil {
		panic(err)
	}
	return reg
}

func storeUserHeader(t *testing.T, v *memVault, gw ids.GatewayID, sub string, reg *registrydomain.Registry, header, value string) {
	t.Helper()
	cred, err := vaultdomain.NewCredential(gw, sub, registrydomain.UserHeaderVaultProvider(reg.ID, header), "", value, "", nil, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Upsert(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
}

func TestApplyUserHeaders_EachCallerSendsTheirOwnValue(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	vault := &memVault{}
	reg := regWithUserHeaders(gw, registrydomain.MCPUserHeader{Name: "X-API-Key", Required: true, Secret: true})
	storeUserHeader(t, vault, gw, "ana", reg, "x-api-key", "ana-key")
	storeUserHeader(t, vault, gw, "bruno", reg, "X-API-Key", "bruno-key")
	r := NewCredentialResolver(nil, vault, &stubConnect{ticket: "t"}, nil, discardLogger())
	rc := mcpConsumer(gw)

	targets := map[string]Target{}
	for _, sub := range []string{"ana", "bruno"} {
		ctx := principalCtx(&identity.Principal{Subject: sub, Method: identity.MethodOAuth})
		target := targetFor(ctx, rc, reg)
		if err := r.Apply(ctx, rc, reg, &target); err != nil {
			t.Fatalf("%s: Apply() = %v", sub, err)
		}
		targets[sub] = target
	}
	if got := targets["ana"].Headers["X-API-Key"]; got != "ana-key" {
		t.Fatalf("ana sent %q", got)
	}
	if got := targets["bruno"].Headers["X-API-Key"]; got != "bruno-key" {
		t.Fatalf("bruno sent %q", got)
	}
	if targets["ana"].Headers["X-Tenant"] != "acme" {
		t.Fatal("shared header dropped")
	}
	if targets["ana"].PinKey == targets["bruno"].PinKey {
		t.Fatal("two callers share an upstream session")
	}
	for _, tg := range targets {
		if strings.Contains(tg.PinKey, "key") {
			t.Fatalf("pin key carries the value: %s", tg.PinKey)
		}
	}
}

func TestApplyUserHeaders_SchemeAndRotation(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	vault := &memVault{}
	reg := regWithUserHeaders(gw, registrydomain.MCPUserHeader{Name: "Authorization", Scheme: "Bearer", Required: true})
	storeUserHeader(t, vault, gw, "ana", reg, "Authorization", "one")
	r := NewCredentialResolver(nil, vault, &stubConnect{}, nil, discardLogger())
	rc := mcpConsumer(gw)
	ctx := principalCtx(&identity.Principal{Subject: "ana"})

	first := targetFor(ctx, rc, reg)
	if err := r.Apply(ctx, rc, reg, &first); err != nil {
		t.Fatal(err)
	}
	if first.Headers["Authorization"] != "Bearer one" {
		t.Fatalf("got %q", first.Headers["Authorization"])
	}
	storeUserHeader(t, vault, gw, "ana", reg, "Authorization", "two")
	second := targetFor(ctx, rc, reg)
	if err := r.Apply(ctx, rc, reg, &second); err != nil {
		t.Fatal(err)
	}
	if first.PinKey == second.PinKey {
		t.Fatal("a replaced value must dial a new session")
	}
}

func TestApplyUserHeaders_MissingValue(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	rc := mcpConsumer(gw)
	ctx := principalCtx(&identity.Principal{Subject: "ana"})

	t.Run("required asks for consent", func(t *testing.T) {
		t.Parallel()
		reg := regWithUserHeaders(gw, registrydomain.MCPUserHeader{Name: "X-API-Key", Required: true})
		r := NewCredentialResolver(nil, &memVault{}, &stubConnect{ticket: "tk"}, nil, discardLogger())
		target := targetFor(ctx, rc, reg)
		err := r.Apply(ctx, rc, reg, &target)
		var consent *ConsentRequiredError
		if !errors.As(err, &consent) || consent.Cause != ConsentCauseUserHeaderMissing || consent.Ticket != "tk" {
			t.Fatalf("Apply() = %v, want consent with ticket", err)
		}
	})
	t.Run("optional is left out", func(t *testing.T) {
		t.Parallel()
		reg := regWithUserHeaders(gw, registrydomain.MCPUserHeader{Name: "X-Account"})
		r := NewCredentialResolver(nil, &memVault{}, &stubConnect{}, nil, discardLogger())
		target := targetFor(ctx, rc, reg)
		if err := r.Apply(ctx, rc, reg, &target); err != nil {
			t.Fatal(err)
		}
		if _, ok := target.Headers["X-Account"]; ok {
			t.Fatal("optional header without a value was sent")
		}
	})
}

func TestApplyUserHeaders_CallerWithoutIndividualIdentity(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	vault := &memVault{}
	rc := mcpConsumer(gw)
	reg := regWithUserHeaders(gw, registrydomain.MCPUserHeader{Name: "X-API-Key", Required: true})
	storeUserHeader(t, vault, gw, "owner", reg, "X-API-Key", "owner-key")
	r := NewCredentialResolver(nil, vault, &stubConnect{}, nil, discardLogger())

	cases := map[string]*identity.Principal{
		"application itself": {Subject: consumerdomain.AppSubject(rc.Consumer.ID), Method: identity.MethodAPIKey},
		"group key": {Subject: "owner", Method: identity.MethodPersonalKey,
			Claims: map[string]any{identity.ClaimKeyGroup: "engineering"}},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := principalCtx(p)
			target := targetFor(ctx, rc, reg)
			err := r.Apply(ctx, rc, reg, &target)
			var notConnected *ApplicationNotConnectedError
			if !errors.As(err, &notConnected) {
				t.Fatalf("Apply() = %v, want ApplicationNotConnectedError", err)
			}
			if _, sent := target.Headers["X-API-Key"]; sent {
				t.Fatal("a value was sent for a caller with no individual identity")
			}
		})
	}
	t.Run("no principal", func(t *testing.T) {
		t.Parallel()
		target := targetFor(context.Background(), rc, reg)
		if err := r.Apply(context.Background(), rc, reg, &target); !errors.Is(err, ErrNoPrincipal) {
			t.Fatalf("Apply() = %v, want ErrNoPrincipal", err)
		}
	})
}

func TestApplyUserHeaders_InstancesHoldSeparateValues(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	vault := &memVault{}
	pre := regWithUserHeaders(gw, registrydomain.MCPUserHeader{Name: "X-API-Key", Required: true})
	pro := regWithUserHeaders(gw, registrydomain.MCPUserHeader{Name: "X-API-Key", Required: true})
	storeUserHeader(t, vault, gw, "ana", pre, "X-API-Key", "pre-key")
	r := NewCredentialResolver(nil, vault, &stubConnect{}, nil, discardLogger())
	rc := mcpConsumer(gw)
	ctx := principalCtx(&identity.Principal{Subject: "ana"})

	target := targetFor(ctx, rc, pro)
	var consent *ConsentRequiredError
	if err := r.Apply(ctx, rc, pro, &target); !errors.As(err, &consent) {
		t.Fatalf("PRO reused PRE's value: %v", err)
	}
}

func TestRefresh_UpstreamRejectsUserHeader(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	vault := userHeaderVault{&memVault{}}
	reg := regWithUserHeaders(gw, registrydomain.MCPUserHeader{Name: "X-API-Key", Required: true})
	storeUserHeader(t, vault.memVault, gw, "ana", reg, "X-API-Key", "stale")
	r := NewCredentialResolver(nil, vault, &stubConnect{ticket: "tk"}, nil, discardLogger()).(*credentialResolver)
	rc := mcpConsumer(gw)
	ctx := principalCtx(&identity.Principal{Subject: "ana"})

	target := targetFor(ctx, rc, reg)
	if err := r.Apply(ctx, rc, reg, &target); err != nil {
		t.Fatal(err)
	}
	var consent *ConsentRequiredError
	if err := r.Refresh(ctx, rc, reg, &target); !errors.As(err, &consent) || consent.Cause != ConsentCauseUserHeaderRejected {
		t.Fatalf("Refresh() = %v, want consent with rejected cause", err)
	}
	next := targetFor(ctx, rc, reg)
	if err := r.Apply(ctx, rc, reg, &next); !errors.As(err, &consent) || consent.Cause != ConsentCauseUserHeaderRejected {
		t.Fatalf("Apply() after a 401 = %v, want the rejected value refused before dialing", err)
	}

	t.Run("a registry without user headers keeps refusing to refresh", func(t *testing.T) {
		t.Parallel()
		plain := regWithAuth(gw, &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeNone})
		tg := targetFor(ctx, rc, plain)
		if err := r.Refresh(ctx, rc, plain, &tg); !errors.Is(err, errCredentialRefreshUnsupported) {
			t.Fatalf("Refresh() = %v, want unsupported", err)
		}
	})
}

func TestRefresh_UserHeaderRejectionIsNarrow(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	rc := mcpConsumer(gw)
	ctx := principalCtx(&identity.Principal{Subject: "ana"})

	t.Run("a key replaced while the call was in flight is kept", func(t *testing.T) {
		t.Parallel()
		vault := userHeaderVault{&memVault{}}
		reg := regWithUserHeaders(gw, registrydomain.MCPUserHeader{Name: "X-API-Key", Required: true})
		storeUserHeader(t, vault.memVault, gw, "ana", reg, "X-API-Key", "old")
		r := NewCredentialResolver(nil, vault, &stubConnect{}, nil, discardLogger()).(*credentialResolver)
		target := targetFor(ctx, rc, reg)
		if err := r.Apply(ctx, rc, reg, &target); err != nil {
			t.Fatal(err)
		}
		storeUserHeader(t, vault.memVault, gw, "ana", reg, "X-API-Key", "new")
		if err := r.Refresh(ctx, rc, reg, &target); !errors.Is(err, errCredentialRefreshUnsupported) {
			t.Fatalf("Refresh() = %v, want the 401 returned as is", err)
		}
		next := targetFor(ctx, rc, reg)
		if err := r.Apply(ctx, rc, reg, &next); err != nil || next.Headers["X-API-Key"] != "new" {
			t.Fatalf("the new key was marked refused: %v %q", err, next.Headers["X-API-Key"])
		}
	})

	t.Run("an auth mode with a credential of its own leaves the keys alone", func(t *testing.T) {
		t.Parallel()
		vault := userHeaderVault{&memVault{}}
		reg, err := registrydomain.NewMCPRegistry(gw, "both", "", &registrydomain.MCPTarget{
			URL:         "https://both.example.com/mcp",
			Auth:        &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer admin"},
			UserHeaders: []registrydomain.MCPUserHeader{{Name: "X-API-Key", Required: true}},
		})
		if err != nil {
			t.Fatal(err)
		}
		storeUserHeader(t, vault.memVault, gw, "ana", reg, "X-API-Key", "ana-key")
		r := NewCredentialResolver(nil, vault, &stubConnect{}, nil, discardLogger()).(*credentialResolver)
		target := targetFor(ctx, rc, reg)
		if err := r.Apply(ctx, rc, reg, &target); err != nil {
			t.Fatal(err)
		}
		if err := r.Refresh(ctx, rc, reg, &target); !errors.Is(err, errCredentialRefreshUnsupported) {
			t.Fatalf("Refresh() = %v, want the 401 returned as is", err)
		}
		next := targetFor(ctx, rc, reg)
		if err := r.Apply(ctx, rc, reg, &next); err != nil {
			t.Fatalf("ana's key was marked refused for the admin's credential: %v", err)
		}
	})
}
