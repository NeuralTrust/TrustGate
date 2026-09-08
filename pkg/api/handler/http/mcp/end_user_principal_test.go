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
