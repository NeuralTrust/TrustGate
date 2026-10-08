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
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestCompilerFillsTheSharedOAuthSecretOnlyForProviderEndpoints(t *testing.T) {
	gw := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	google := sharedClientRegistry(gw, "shared-id")
	google.Name = "google"
	google.MCPTarget.Auth.AuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
	google.MCPTarget.Auth.TokenURL = "https://oauth2.googleapis.com/token"
	elsewhere := sharedClientRegistry(gw, "shared-id")
	elsewhere.Name = "elsewhere"
	elsewhere.MCPTarget.Auth.AuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
	elsewhere.MCPTarget.Auth.TokenURL = "https://idp.example.com/token"

	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: gw}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{gw.String(): {google, elsewhere}}},
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
		secrets[reg.Name] = reg.MCPTarget.Auth.ClientSecret
	}
	if secrets["google"] != "shared-secret" {
		t.Fatalf("provider endpoints: secret = %q, want it filled in", secrets["google"])
	}
	if secrets["elsewhere"] != "" {
		t.Fatalf("another token endpoint got the shared secret: %q", secrets["elsewhere"])
	}
}
