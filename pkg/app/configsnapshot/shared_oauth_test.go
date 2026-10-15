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

package configsnapshot_test

import (
	"context"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func sharedClientRegistry(gatewayID ids.GatewayID, clientID string) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: gatewayID,
		Type:      registrydomain.TypeMCP,
		MCPTarget: &registrydomain.MCPTarget{
			Code: mcpoauth.GmailCode,
			Auth: &registrydomain.MCPAuth{
				Mode:         registrydomain.MCPAuthModeForwarded,
				ClientID:     clientID,
				AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL:     "https://oauth2.googleapis.com/token",
			},
		},
	}
}

// The shared client's secret is not stored on the registry, so data planes
// that refresh from the snapshot alone get it from the compiled snapshot.
func TestCompilerFillsTheSharedOAuthSecretIntoTheSnapshot(t *testing.T) {
	gw := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	stored := sharedClientRegistry(gw, "shared-id")
	other := sharedClientRegistry(gw, "customer-own-id")
	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: gw}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{gw.String(): {stored, other}}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
		appsnapshot.WithSharedOAuth(mcpoauth.NewGoogleWorkspace("shared-id", "shared-secret")),
	)

	snapshot, err := compiler.Compile(context.Background())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	secrets := map[string]string{}
	for _, reg := range snapshot.Data().Registries {
		secrets[reg.MCPTarget.Auth.ClientID] = reg.MCPTarget.Auth.ClientSecret
	}
	if secrets["shared-id"] != "shared-secret" {
		t.Fatalf("shared client secret = %q, want it filled in", secrets["shared-id"])
	}
	if secrets["customer-own-id"] != "" {
		t.Fatalf("a registry with its own client got %q", secrets["customer-own-id"])
	}
	if stored.MCPTarget.Auth.ClientSecret != "" {
		t.Fatal("the registry read from the repository was modified")
	}
}
