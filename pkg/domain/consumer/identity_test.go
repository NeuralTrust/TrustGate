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

package consumer

import (
	"errors"
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestIdentity_DefaultsToTheApplication(t *testing.T) {
	t.Parallel()
	c, err := New(mcpParams())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.ActsForUsers() || c.Identity.Source != "" || c.Identity.EndUserHeader {
		t.Fatalf("a consumer without identity acts as the application, got %+v", c.Identity)
	}
}

func TestIdentity_ActsForUsersDefaultsToPlatformSource(t *testing.T) {
	t.Parallel()
	p := mcpParams()
	p.Identity = &Identity{ActsForUsers: true}
	c, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !c.Identity.PlatformUsers() || c.Identity.AppUsers() {
		t.Fatalf("acts_for_users without a source must default to platform, got %+v", c.Identity)
	}
}

func TestIdentity_SourceIsNormalised(t *testing.T) {
	t.Parallel()
	p := mcpParams()
	p.Identity = &Identity{ActsForUsers: true, Source: " App "}
	c, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !c.Identity.AppUsers() {
		t.Fatalf("source must be trimmed and lower-cased, got %q", c.Identity.Source)
	}
	// Turning the switch off drops a stale source instead of failing.
	off := Identity{ActsForUsers: false, Source: IdentitySourceApp}
	off.Normalize(TypeMCP)
	if off.Source != "" {
		t.Fatalf("source must be cleared when acts_for_users is off, got %q", off.Source)
	}
}

func TestIdentity_Validate_Rejects(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		typ      Type
		identity Identity
	}{
		"acts_for_users on an LLM consumer":  {TypeLLM, Identity{ActsForUsers: true, Source: IdentitySourcePlatform}},
		"unknown source":                     {TypeMCP, Identity{ActsForUsers: true, Source: "ldap"}},
		"source without acts_for_users":      {TypeMCP, Identity{Source: IdentitySourcePlatform}},
		"end_user_header on an MCP consumer": {TypeMCP, Identity{EndUserHeader: true}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.identity.Validate(tc.typ)
			if !errors.Is(err, ErrInvalidIdentity) || !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("err = %v, want ErrInvalidIdentity", err)
			}
		})
	}
}

func TestIdentity_EndUserHeaderOnLLM(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.Identity = &Identity{EndUserHeader: true}
	c, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !c.Identity.EndUserHeader || c.ActsForUsers() {
		t.Fatalf("LLM attribution header must be accepted without acting for users, got %+v", c.Identity)
	}
}

func TestBuildStoreConsumer_ActsForPlatformUsers(t *testing.T) {
	t.Parallel()
	c := BuildStoreConsumer(ids.New[ids.GatewayKind]())
	if !c.Identity.PlatformUsers() {
		t.Fatalf("the Store acts for platform users, got %+v", c.Identity)
	}
}

func TestValidateAuth_IdentityRules(t *testing.T) {
	t.Parallel()
	app := &Consumer{Type: TypeMCP}
	platform := &Consumer{Type: TypeMCP, Identity: Identity{ActsForUsers: true, Source: IdentitySourcePlatform}}
	appUsers := &Consumer{Type: TypeMCP, Identity: Identity{ActsForUsers: true, Source: IdentitySourceApp}}

	allowed := []struct {
		name string
		c    *Consumer
		auth authdomain.Type
	}{
		{"application with api key", app, authdomain.TypeAPIKey},
		{"application with oauth2", app, authdomain.TypeOAuth2},
		{"platform users with oauth2", platform, authdomain.TypeOAuth2},
		{"app users with api key", appUsers, authdomain.TypeAPIKey},
		{"app users with mtls", appUsers, authdomain.TypeMTLS},
	}
	for _, tc := range allowed {
		if err := ValidateAuth(tc.c, tc.auth); err != nil {
			t.Fatalf("%s: unexpected error %v", tc.name, err)
		}
	}

	rejected := []struct {
		name string
		c    *Consumer
		auth authdomain.Type
	}{
		{"platform users with api key", platform, authdomain.TypeAPIKey},
		{"platform users with mtls", platform, authdomain.TypeMTLS},
		{"app users with oauth2", appUsers, authdomain.TypeOAuth2},
	}
	for _, tc := range rejected {
		if err := ValidateAuth(tc.c, tc.auth); !errors.Is(err, commonerrors.ErrConflict) {
			t.Fatalf("%s: err = %v, want ErrConflict", tc.name, err)
		}
	}
	if err := ValidateAuth(nil, authdomain.TypeAPIKey); err != nil {
		t.Fatalf("nil consumer must be a no-op, got %v", err)
	}
}

func TestValidateEndUser(t *testing.T) {
	t.Parallel()
	if err := ValidateEndUser(" user_123 "); err != nil {
		t.Fatalf("a trimmed opaque id is valid, got %v", err)
	}
	for name, id := range map[string]string{
		"empty":    "   ",
		"too long": strings.Repeat("u", MaxEndUserLength+1),
		"control":  "user\n123",
	} {
		if err := ValidateEndUser(id); !errors.Is(err, ErrInvalidEndUser) || !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("%s: err = %v, want ErrInvalidEndUser", name, err)
		}
	}
}

func TestEndUserSubject_IsNamespacedByConsumer(t *testing.T) {
	t.Parallel()
	a := ids.New[ids.ConsumerKind]()
	b := ids.New[ids.ConsumerKind]()
	if EndUserSubject(a, " user_123 ") != "app:"+a.String()+":user_123" {
		t.Fatalf("unexpected subject %q", EndUserSubject(a, " user_123 "))
	}
	if EndUserSubject(a, "user_123") == EndUserSubject(b, "user_123") {
		t.Fatal("two applications naming the same user must never share a subject")
	}
	if !strings.HasPrefix(EndUserSubject(a, "sub-of-a-platform-user"), "app:") {
		t.Fatal("app-identified subjects carry the app: prefix so they cannot collide with token subjects")
	}
}

func TestValidateAuthConfig_PlatformUsersNeedAnInteractiveIdP(t *testing.T) {
	t.Parallel()
	platform := &Consumer{Type: TypeMCP, Identity: Identity{ActsForUsers: true, Source: IdentitySourcePlatform}}
	validateOnly := &authdomain.Auth{Type: authdomain.TypeOAuth2, Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{Issuer: "https://idp", JWKSURL: "https://idp/jwks"}}}
	interactive := &authdomain.Auth{Type: authdomain.TypeOAuth2, Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{Issuer: "https://idp", ClientID: "gateway"}}}
	if err := ValidateAuthConfig(platform, validateOnly); !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("a validation-only IdP cannot broker a login, got %v", err)
	}
	if err := ValidateAuthConfig(platform, interactive); err != nil {
		t.Fatalf("an IdP with a registered client brokers the login, got %v", err)
	}
	// Applications validating their own tokens keep using validation-only IdPs.
	app := &Consumer{Type: TypeMCP}
	if err := ValidateAuthConfig(app, validateOnly); err != nil {
		t.Fatalf("an application consumer may use a validation-only IdP, got %v", err)
	}
	if err := ValidateAuthConfig(nil, validateOnly); err != nil {
		t.Fatalf("nil consumer is a no-op, got %v", err)
	}
}

// WantsSignIn is shared by the request-time auth chain and the authorize-time
// provider selection, so its contract is pinned here rather than in either
// caller (RUN-1501).
func TestConsumer_WantsSignIn(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()

	tests := []struct {
		name string
		c    *Consumer
		want bool
	}{
		// A nil consumer means the resource matched nothing. Callers read this
		// as "may broker a login", so it must stay false and fail closed.
		{name: "nil consumer fails closed"},
		{
			name: "platform source",
			c:    &Consumer{Type: TypeMCP, Identity: Identity{ActsForUsers: true, Source: IdentitySourcePlatform}},
			want: true,
		},
		{
			name: "app source names its own users and authenticates as a machine",
			c:    &Consumer{Type: TypeMCP, Identity: Identity{ActsForUsers: true, Source: IdentitySourceApp}},
		},
		{name: "no identity", c: &Consumer{Type: TypeMCP}},
		{name: "store consumer", c: BuildStoreConsumer(gw), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.c.WantsSignIn(); got != tt.want {
				t.Fatalf("WantsSignIn() = %v, want %v", got, tt.want)
			}
		})
	}
}
