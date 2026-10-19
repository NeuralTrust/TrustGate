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
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestEmptySurfaceInsteadOfError(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	cons := &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Type: consumerdomain.TypeMCP}
	rc := &appconsumer.RoutableConsumer{Consumer: cons}
	store := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}

	// Who is asking, not how the consumer was configured: the same consumer
	// answers one way to the application itself and another to a person.
	asApp := identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: consumerdomain.AppSubject(cons.ID),
		Method:  identity.MethodAPIKey,
	})
	asPerson := identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: consumerdomain.EndUserSubject(cons.ID, "user_123"),
		Method:  identity.MethodAPIKey,
	})

	// A server waiting on an account degrades to an empty list for everyone:
	// a pending consent, and a server with no account for this caller — the
	// application itself on a per-user instance included (ENG-1787).
	for name, waiting := range map[string]error{
		"a pending consent":                     &ConsentRequiredError{Provider: "github"},
		"a per-user instance that names nobody": &ApplicationNotConnectedError{Provider: "com.google.workspace/drive", Registry: "Google Drive"},
		"a shared account nobody has connected": &ApplicationNotConnectedError{Provider: "linear", Registry: "Linear", Shared: true},
	} {
		for _, ctx := range []context.Context{asApp, asPerson} {
			if !emptySurfaceInsteadOfError(ctx, rc, waiting) {
				t.Fatalf("%s must yield an empty surface, not an error", name)
			}
		}
	}
	// Nothing bound is an empty surface for the application too: a client lists
	// tools while connecting, and a fault there fails the connection. An
	// unreachable upstream is still a fault when the request runs as the
	// application, because registries were bound and could not be reached.
	if !emptySurfaceInsteadOfError(asApp, rc, ErrNoMCPRegistries) {
		t.Fatal("an application with nothing bound lists an empty surface")
	}
	if !emptySurfaceInsteadOfError(asPerson, rc, ErrNoMCPRegistries) {
		t.Fatal("a person with nothing connected lists an empty surface")
	}
	if !emptySurfaceInsteadOfError(asApp, store, ErrNoMCPRegistries) {
		t.Fatal("the Store is per person whoever is asking")
	}
	if emptySurfaceInsteadOfError(asApp, rc, ErrUpstreamUnavailable) {
		t.Fatal("an unreachable upstream is still a fault for the application")
	}
	if !emptySurfaceInsteadOfError(asPerson, rc, ErrUpstreamUnavailable) {
		t.Fatal("an unreachable upstream degrades to an empty surface for a person")
	}
	if emptySurfaceInsteadOfError(asPerson, rc, errors.New("boom")) {
		t.Fatal("other errors still fail")
	}
}
