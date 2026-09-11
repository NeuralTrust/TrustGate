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

package store

import (
	"testing"

	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// The rule that decides this moved into the catalog: each entry declares
// `self_service`, and the seed is checked against every entry's own facts in
// pkg/app/catalog. All that is left here is that the Store reads the entry's
// answer rather than guessing at its auth shape — the table of shapes this test
// used to carry is what the seed check now covers, over the real 198 entries
// instead of invented ones.
func TestCatalogNeedsAdminCredential(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry catalogdomain.MCPServer
		want  bool
	}{
		{
			name: "a server a user can install alone",
			entry: catalogdomain.MCPServer{
				Code: "app.linear/mcp", SelfService: true,
				AuthHint: "oauth", OAuth: &catalogdomain.MCPOAuth{Required: true, Registration: "auto"},
			},
			want: false,
		},
		{
			name: "a server whose credential only an admin holds",
			entry: catalogdomain.MCPServer{
				Code: "com.slack/mcp", SelfService: false,
				AuthHint: "oauth", OAuth: &catalogdomain.MCPOAuth{Required: true, Registration: "manual"},
			},
			want: true,
		},
		{
			// The conservative default: an entry nobody declared is treated as
			// needing an admin, never the other way round.
			name:  "an entry with nothing declared",
			entry: catalogdomain.MCPServer{Code: "com.unknown/mcp"},
			want:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := catalogNeedsAdminCredential(tc.entry); got != tc.want {
				t.Fatalf("catalogNeedsAdminCredential = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCatalogRegistry_DualAuthMaterialisesForwarded: a server offering both an
// API key and OAuth materialises with forwarded (OAuth) auth — the one method a
// self-service user can complete alone — and the result validates.
func TestCatalogRegistry_DualAuthMaterialisesForwarded(t *testing.T) {
	reg, err := catalogRegistry(catalogdomain.MCPServer{
		Code: "com.dual/mcp", URL: "https://mcp.dual.example/mcp", Transport: "streamable-http",
		AuthHint: "static", AuthMethods: []string{"static", "oauth"}, RequiresAuth: true,
		AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "Authorization", Secret: true}},
		OAuth:       &catalogdomain.MCPOAuth{Registration: "auto"},
	}, ids.New[ids.GatewayKind]())
	if err != nil {
		t.Fatalf("catalogRegistry: %v", err)
	}
	if reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeForwarded || reg.MCPTarget.Auth.Registration != registrydomain.RegistrationAuto {
		t.Fatalf("dual-auth must materialise as forwarded/auto, got %+v", reg.MCPTarget.Auth)
	}
	if err := reg.MCPTarget.Validate(); err != nil {
		t.Fatalf("materialised dual-auth target must validate: %v", err)
	}
}

// TestCatalogRegistry_SecretURLVariableMapsToNoAuth: a Bright Data-like server
// (token in the query string, no auth header) needs no upstream header; the
// per-user token is substituted into the URL from the vault. Its target validates
// so it can be self-served.
func TestCatalogRegistry_SecretURLVariableMapsToNoAuth(t *testing.T) {
	reg, err := catalogRegistry(catalogdomain.MCPServer{
		Code: "com.brightdata/mcp", URL: "https://mcp.brightdata.com/mcp?token={token}", Transport: "streamable-http",
		AuthHint: "static", RequiresAuth: true, AuthMethods: []string{"static"},
		URLVariables: []catalogdomain.MCPURLVariable{{Name: "token", Required: true, Secret: true, In: "query"}},
	}, ids.New[ids.GatewayKind]())
	if err != nil {
		t.Fatalf("catalogRegistry: %v", err)
	}
	if reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeNone {
		t.Fatalf("secret-URL-variable server must map to auth none, got %+v", reg.MCPTarget.Auth)
	}
	if err := reg.MCPTarget.Validate(); err != nil {
		t.Fatalf("materialised target must validate: %v", err)
	}
}

// TestCatalogRegistry_StaticHeaderOnlyDoesNotValidate documents why the installer
// refuses to self-serve an API-key-only server: the catalog has no value for the
// header, and a static auth without a value is invalid.
func TestCatalogRegistry_StaticHeaderOnlyDoesNotValidate(t *testing.T) {
	reg, err := catalogRegistry(catalogdomain.MCPServer{
		Code: "com.semrush/mcp", URL: "https://mcp.semrush.com/mcp", Transport: "streamable-http",
		AuthHint: "static", AuthMethods: []string{"static"}, RequiresAuth: true,
		AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "Authorization", Secret: true}},
	}, ids.New[ids.GatewayKind]())
	if err != nil {
		t.Fatalf("catalogRegistry: %v", err)
	}
	if reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeStatic || reg.MCPTarget.Auth.Header != "Authorization" {
		t.Fatalf("api-key server must map to static with its header, got %+v", reg.MCPTarget.Auth)
	}
	if err := reg.MCPTarget.Validate(); err == nil {
		t.Fatal("a static auth with no value must not validate (hence RequiresAdminSetup)")
	}
}
