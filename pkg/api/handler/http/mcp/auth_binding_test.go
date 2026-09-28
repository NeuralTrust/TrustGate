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
)

func TestConsumerAdmitsPrincipal(t *testing.T) {
	open := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP}
	bound := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, AuthBinding: consumerdomain.AuthBinding{
		AllowedClientIDs:           []string{"app-a"},
		AllowedCertificateSubjects: []string{"svc.internal"},
	}}

	if !consumerAdmitsPrincipal(open, nil) || !consumerAdmitsPrincipal(bound, nil) {
		t.Fatal("no principal (built-in provider bootstrap) has nothing to bind")
	}
	if consumerAdmitsPrincipal(nil, &identity.Principal{Method: identity.MethodJWT}) {
		t.Fatal("no consumer admits nobody")
	}

	jwtFor := func(client string) *identity.Principal {
		return &identity.Principal{Method: identity.MethodJWT, Subject: "user", Claims: map[string]any{"azp": client}}
	}
	if !consumerAdmitsPrincipal(open, jwtFor("anyone")) {
		t.Fatal("an unbound consumer admits any verified client")
	}
	if !consumerAdmitsPrincipal(bound, jwtFor("app-a")) || consumerAdmitsPrincipal(bound, jwtFor("app-b")) {
		t.Fatal("a bound consumer admits only tokens issued to its clients")
	}
	introspected := &identity.Principal{Method: identity.MethodIntrospection, Claims: map[string]any{"client_id": "app-b"}}
	if consumerAdmitsPrincipal(bound, introspected) {
		t.Fatal("introspected opaque tokens are bound by client_id too")
	}

	cert := func(cn string, dns ...string) *identity.Principal {
		return &identity.Principal{Method: identity.MethodMTLS, Subject: cn, Claims: map[string]any{"common_name": cn, "dns_names": dns}}
	}
	if !consumerAdmitsPrincipal(bound, cert("svc.internal")) || !consumerAdmitsPrincipal(bound, cert("other", "svc.internal")) {
		t.Fatal("an allowed common name or SAN DNS name admits the certificate")
	}
	if consumerAdmitsPrincipal(bound, cert("other", "elsewhere")) {
		t.Fatal("a certificate naming none of the allowed subjects is refused")
	}
	// Claims decoded from JSON carry []any rather than []string.
	decoded := &identity.Principal{Method: identity.MethodMTLS, Claims: map[string]any{"common_name": "other", "dns_names": []any{"svc.internal"}}}
	if !consumerAdmitsPrincipal(bound, decoded) {
		t.Fatal("SAN names decoded as []any must still match")
	}

	apiKey := &identity.Principal{Method: identity.MethodAPIKey, Subject: "key"}
	if !consumerAdmitsPrincipal(bound, apiKey) {
		t.Fatal("an API key is bound to one consumer already; the binding does not apply")
	}
}

// TestConsumerAdmitsPrincipalBindsEveryBearerMethod pins the RUN-1501 split of
// the single "jwt" method into a gateway-issued and an external-IdP value. Each
// bearer method must still reach the consumer's client binding: a method that
// fell through to the permissive default would let a token issued to any client
// enter a consumer that named the clients it accepts.
func TestConsumerAdmitsPrincipalBindsEveryBearerMethod(t *testing.T) {
	bound := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, AuthBinding: consumerdomain.AuthBinding{
		AllowedClientIDs: []string{"app-a"},
	}}

	tests := map[string]struct {
		method identity.Method
		bound  bool
	}{
		"a gateway-issued session token": {identity.MethodOAuth, true},
		"an external identity provider":  {identity.MethodExternalJWT, true},
		"the legacy undifferentiated":    {identity.MethodJWT, true},
		"an introspected opaque token":   {identity.MethodIntrospection, true},
		"an api key":                     {identity.MethodAPIKey, false},
		"a client certificate":           {identity.MethodMTLS, false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			allowed := &identity.Principal{Method: tc.method, Subject: "user", Claims: map[string]any{"azp": "app-a"}}
			refused := &identity.Principal{Method: tc.method, Subject: "user", Claims: map[string]any{"azp": "app-b"}}
			if !consumerAdmitsPrincipal(bound, allowed) {
				t.Fatalf("%s naming an allowed client must be admitted", name)
			}
			if got := consumerAdmitsPrincipal(bound, refused); got == tc.bound {
				t.Fatalf("%s naming a disallowed client: admitted=%v, want bound=%v", name, got, tc.bound)
			}
		})
	}
}

func TestMethodPredicates(t *testing.T) {
	tests := map[identity.Method]struct {
		bearer    bool
		assertion bool
	}{
		identity.MethodOAuth:         {true, false},
		identity.MethodExternalJWT:   {true, true},
		identity.MethodJWT:           {true, true},
		identity.MethodIntrospection: {true, false},
		identity.MethodAPIKey:        {false, false},
		identity.MethodMTLS:          {false, false},
		identity.Method(""):          {false, false},
	}

	for method, want := range tests {
		t.Run(string(method), func(t *testing.T) {
			if got := method.IsBearerToken(); got != want.bearer {
				t.Fatalf("%q.IsBearerToken() = %v, want %v", method, got, want.bearer)
			}
			if got := method.IsExternalIdPAssertion(); got != want.assertion {
				t.Fatalf("%q.IsExternalIdPAssertion() = %v, want %v", method, got, want.assertion)
			}
		})
	}
}
