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
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestEndUserPrincipal(t *testing.T) {
	cons := &consumerdomain.Consumer{
		ID:       ids.New[ids.ConsumerKind](),
		Type:     consumerdomain.TypeMCP,
		Identity: consumerdomain.Identity{ActsForUsers: true, Source: consumerdomain.IdentitySourceApp},
	}
	app := &identity.Principal{Subject: "backend-key", Method: identity.MethodAPIKey}

	p := endUserPrincipal(cons, app, " user_123 ")
	if p.Subject != consumerdomain.EndUserSubject(cons.ID, "user_123") {
		t.Fatalf("subject = %q, want the consumer-namespaced end user", p.Subject)
	}
	if p.Method != identity.MethodAPIKey {
		t.Fatalf("method = %q, want the application's credential method", p.Method)
	}
	if p.Claims["end_user"] != "user_123" || p.Claims["consumer_id"] != cons.ID.String() || p.Claims["app_subject"] != "backend-key" {
		t.Fatalf("claims must keep the end user and the application's credential for audit, got %v", p.Claims)
	}
	if p.Groups() != nil {
		t.Fatal("an app-identified end user carries no groups: Access never applies")
	}

	// Without an application principal (defensive) the subject is still
	// namespaced and the method falls back to api_key.
	bare := endUserPrincipal(cons, nil, "u")
	if bare.Method != identity.MethodAPIKey || bare.Claims["app_subject"] != nil {
		t.Fatalf("unexpected bare principal %+v", bare)
	}
}

func TestMachineCredential(t *testing.T) {
	if !machineCredential(&identity.Principal{Method: identity.MethodAPIKey}) || !machineCredential(&identity.Principal{Method: identity.MethodMTLS}) {
		t.Fatal("an API key or a client certificate is the application's own credential")
	}
	if machineCredential(&identity.Principal{Method: identity.MethodJWT}) || machineCredential(nil) {
		t.Fatal("a user login (JWT / session) is not the application's credential")
	}
}

// A consumer that acts as the application runs as the application, so its
// upstream accounts survive whatever happens to the credential that opened the
// door: rotate the key, rename it, add a second one, swap it for a certificate,
// and the same subject keeps reaching the same accounts.
func TestAppPrincipal(t *testing.T) {
	cons := &consumerdomain.Consumer{
		ID:   ids.New[ids.ConsumerKind](),
		Type: consumerdomain.TypeMCP,
	}
	callers := map[string]*identity.Principal{
		"an api key":           {Subject: "prod", Method: identity.MethodAPIKey},
		"a renamed api key":    {Subject: "prod-rotated-2026", Method: identity.MethodAPIKey},
		"a client certificate": {Subject: "CN=assistant", Method: identity.MethodMTLS},
	}
	for name, caller := range callers {
		t.Run(name, func(t *testing.T) {
			p := appPrincipal(cons, caller)
			if p.Subject != consumerdomain.AppSubject(cons.ID) {
				t.Fatalf("subject = %q, want the consumer's own subject", p.Subject)
			}
			if p.Method != caller.Method {
				t.Fatalf("method = %q, want the credential's own method %q", p.Method, caller.Method)
			}
			if p.Claims[identity.ClaimCredentialSubject] != caller.Subject {
				t.Fatalf("the credential that called must survive for audit, got %v", p.Claims)
			}
			if p.Claims["consumer_id"] != cons.ID.String() {
				t.Fatalf("claims must name the application, got %v", p.Claims)
			}
		})
	}

	// A token an upstream forwards or exchanges is the caller's, not the
	// subject's: dropping it here would break passthrough on a machine consumer.
	bearer := &identity.Principal{
		Subject: "svc-client", Method: identity.MethodJWT, Issuer: "https://idp",
		Scopes: []string{"mcp.read"}, RawToken: "raw-token", Claims: map[string]any{"azp": "svc"},
	}
	p := appPrincipal(cons, bearer)
	if p.RawToken != "raw-token" || p.Issuer != "https://idp" || len(p.Scopes) != 1 || p.Claims["azp"] != "svc" {
		t.Fatalf("everything but the subject must carry over, got %+v", p)
	}
	if bearer.Subject != "svc-client" || bearer.Claims[identity.ClaimCredentialSubject] != nil {
		t.Fatal("the caller's own principal must not be mutated")
	}

	// Defensive: no caller at all still yields a namespaced subject.
	if bare := appPrincipal(cons, nil); bare.Subject != consumerdomain.AppSubject(cons.ID) ||
		bare.Method != identity.MethodAPIKey {
		t.Fatalf("unexpected bare principal %+v", bare)
	}
}
