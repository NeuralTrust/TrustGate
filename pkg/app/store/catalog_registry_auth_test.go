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

func TestCatalogNeedsAdminCredential(t *testing.T) {
	cases := []struct {
		name  string
		entry catalogdomain.MCPServer
		want  bool
	}{
		{
			name: "api key header only (explicit methods)",
			entry: catalogdomain.MCPServer{
				AuthHint: "static", AuthMethods: []string{"static"},
				AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "Authorization"}},
			},
			want: true,
		},
		{
			name: "api key header only (derived from hint)",
			entry: catalogdomain.MCPServer{
				AuthHint:    "static",
				AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "X-API-Key"}},
			},
			want: true,
		},
		{
			name:  "static hint with no credential slot at all",
			entry: catalogdomain.MCPServer{AuthHint: "static", RequiresAuth: true},
			want:  true,
		},
		{
			name: "dual auth: api key + oauth",
			entry: catalogdomain.MCPServer{
				AuthHint: "static", AuthMethods: []string{"static", "oauth"},
				AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "Authorization"}},
				OAuth:       &catalogdomain.MCPOAuth{Registration: "auto"},
			},
			want: false,
		},
		{
			name:  "dual auth derived (static hint but an oauth spec)",
			entry: catalogdomain.MCPServer{AuthHint: "static", AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "Authorization"}}, OAuth: &catalogdomain.MCPOAuth{}},
			want:  false,
		},
		{
			name:  "oauth only",
			entry: catalogdomain.MCPServer{AuthHint: "oauth", OAuth: &catalogdomain.MCPOAuth{Required: true, Registration: "auto"}},
			want:  false,
		},
		{
			name: "secret url variable (per-user token in the URL, no header)",
			entry: catalogdomain.MCPServer{
				AuthHint: "static", RequiresAuth: true, AuthMethods: []string{"static"},
				URLVariables: []catalogdomain.MCPURLVariable{{Name: "token", Required: true, Secret: true, In: "query"}},
			},
			want: false,
		},
		{
			name:  "public server",
			entry: catalogdomain.MCPServer{AuthHint: "none"},
			want:  false,
		},
		{
			name: "oauth manual registration without a platform client",
			entry: catalogdomain.MCPServer{AuthHint: "oauth", OAuth: &catalogdomain.MCPOAuth{
				Required: true, Registration: "manual", AuthorizeURL: "https://x/authorize", TokenURL: "https://x/token",
			}},
			want: true,
		},
		{
			name: "oauth manual registration with a platform-held client",
			entry: catalogdomain.MCPServer{AuthHint: "oauth", PlatformClient: true, OAuth: &catalogdomain.MCPOAuth{
				Required: true, Registration: "manual", AuthorizeURL: "https://x/authorize", TokenURL: "https://x/token",
			}},
			want: false,
		},
		{
			name:  "required oauth with undeclared registration (canonicalised to manual)",
			entry: catalogdomain.MCPServer{AuthHint: "oauth", OAuth: &catalogdomain.MCPOAuth{Required: true}},
			want:  true,
		},
		{
			name:  "client_credentials grant (admin-provided client)",
			entry: catalogdomain.MCPServer{AuthHint: "oauth", OAuth: &catalogdomain.MCPOAuth{Required: true, GrantType: "client_credentials", TokenURL: "https://x/token"}},
			want:  true,
		},
	}
	for _, tc := range cases {
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
