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

package grpc

import (
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "datacore"
	testAudience = "trustgate-config-sync"
	testSecret   = "config-sync-shared-secret"
	otherSecret  = "a-different-secret"
)

func newSignedTestConfig(t *testing.T) config.ConfigSyncConfig {
	t.Helper()
	return config.ConfigSyncConfig{
		AuthMode:    config.ConfigSyncAuthModeSigned,
		JWTSecret:   testSecret,
		JWTIssuer:   testIssuer,
		JWTAudience: testAudience,
	}
}

func mint(t *testing.T, secret string, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	var (
		signed string
		err    error
	)
	if method == jwt.SigningMethodNone {
		signed, err = token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	} else {
		signed, err = token.SignedString([]byte(secret))
	}
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   testIssuer,
		"aud":   testAudience,
		"scope": "org_1",
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
}

func TestJWTAuthenticator_ValidTokenExtractsScope(t *testing.T) {
	auth, err := newJWTAuthenticator(newSignedTestConfig(t))
	if err != nil {
		t.Fatalf("newJWTAuthenticator: %v", err)
	}
	scope, err := authenticate(auth, mint(t, testSecret, jwt.SigningMethodHS256, validClaims()))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if scope != "org_1" {
		t.Fatalf("scope = %q, want org_1", scope)
	}
}

func TestJWTAuthenticator_RotationAcceptsPreviousSecret(t *testing.T) {
	cfg := newSignedTestConfig(t)
	cfg.JWTSecret = "new-secret"
	cfg.JWTSecretPrevious = testSecret
	auth, err := newJWTAuthenticator(cfg)
	if err != nil {
		t.Fatalf("newJWTAuthenticator: %v", err)
	}
	for _, secret := range []string{"new-secret", testSecret} {
		scope, err := authenticate(auth, mint(t, secret, jwt.SigningMethodHS256, validClaims()))
		if err != nil {
			t.Fatalf("authenticate with %q: %v", secret, err)
		}
		if scope != "org_1" {
			t.Fatalf("scope = %q, want org_1", scope)
		}
	}
}

func TestJWTAuthenticator_Rejects(t *testing.T) {
	auth, err := newJWTAuthenticator(newSignedTestConfig(t))
	if err != nil {
		t.Fatalf("newJWTAuthenticator: %v", err)
	}

	cases := map[string]string{
		"empty":         "",
		"garbage":       "not-a-jwt",
		"alg_none":      mint(t, testSecret, jwt.SigningMethodNone, validClaims()),
		"bad_signature": mint(t, otherSecret, jwt.SigningMethodHS256, validClaims()),
		"expired": mint(t, testSecret, jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": testIssuer, "aud": testAudience, "scope": "org_1",
			"exp": time.Now().Add(-time.Hour).Unix(),
		}),
		"no_exp": mint(t, testSecret, jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": testIssuer, "aud": testAudience, "scope": "org_1",
		}),
		"wrong_issuer": mint(t, testSecret, jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": "evil", "aud": testAudience, "scope": "org_1",
			"exp": time.Now().Add(time.Hour).Unix(),
		}),
		"wrong_audience": mint(t, testSecret, jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": testIssuer, "aud": "other", "scope": "org_1",
			"exp": time.Now().Add(time.Hour).Unix(),
		}),
		"missing_scope": mint(t, testSecret, jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": testIssuer, "aud": testAudience,
			"exp": time.Now().Add(time.Hour).Unix(),
		}),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := authenticate(auth, token); err == nil {
				t.Fatalf("expected rejection for %s", name)
			}
		})
	}
}

func TestSharedAuthenticator(t *testing.T) {
	auth := newSharedAuthenticator(config.ConfigSyncConfig{Token: "tok", TokenPrevious: "old"})
	for _, tok := range []string{"tok", "old"} {
		scope, err := authenticate(auth, tok)
		if err != nil {
			t.Fatalf("authenticate(%q): %v", tok, err)
		}
		if scope != "" {
			t.Fatalf("shared scope = %q, want empty", scope)
		}
	}
	if _, err := authenticate(auth, "wrong"); err == nil {
		t.Fatal("expected rejection for wrong token")
	}
	unconfigured := newSharedAuthenticator(config.ConfigSyncConfig{})
	if _, err := authenticate(unconfigured, "anything"); err == nil {
		t.Fatal("expected rejection when no token configured")
	}
}

func TestCompositeAuthenticator(t *testing.T) {
	cfg := newSignedTestConfig(t)
	cfg.AuthMode = config.ConfigSyncAuthModeComposite
	cfg.Token = "shared-tok"
	cfg.TokenPrevious = "old-tok"
	auth, err := newCompositeAuthenticator(cfg)
	if err != nil {
		t.Fatalf("newCompositeAuthenticator: %v", err)
	}

	scope, err := authenticate(auth, mint(t, testSecret, jwt.SigningMethodHS256, validClaims()))
	if err != nil {
		t.Fatalf("jwt authenticate: %v", err)
	}
	if scope != "org_1" {
		t.Fatalf("jwt scope = %q, want org_1", scope)
	}

	for _, tok := range []string{"shared-tok", "old-tok"} {
		scope, err := authenticate(auth, tok)
		if err != nil {
			t.Fatalf("shared authenticate(%q): %v", tok, err)
		}
		if scope != "" {
			t.Fatalf("shared scope = %q, want empty (global)", scope)
		}
	}

	for name, bearer := range map[string]string{
		"empty":         "",
		"garbage":       "not-a-jwt",
		"wrong_token":   "nope",
		"bad_signature": mint(t, otherSecret, jwt.SigningMethodHS256, validClaims()),
		"expired": mint(t, testSecret, jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": testIssuer, "aud": testAudience, "scope": "org_1",
			"exp": time.Now().Add(-time.Hour).Unix(),
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := authenticate(auth, bearer); err == nil {
				t.Fatalf("expected rejection for %s", name)
			}
		})
	}
}

func TestNewAuthInterceptor_Composite(t *testing.T) {
	cfg := newSignedTestConfig(t)
	cfg.AuthMode = config.ConfigSyncAuthModeComposite
	cfg.Token = "shared-tok"
	interceptor, err := NewAuthInterceptor(&config.Config{ConfigSync: cfg}, discardLogger(), nil)
	if err != nil {
		t.Fatalf("NewAuthInterceptor composite: %v", err)
	}
	if _, ok := interceptor.authenticator.(*compositeAuthenticator); !ok {
		t.Fatalf("authenticator = %T, want *compositeAuthenticator", interceptor.authenticator)
	}
}

func TestNewAuthInterceptor_SignedRequiresSecret(t *testing.T) {
	_, err := NewAuthInterceptor(&config.Config{ConfigSync: config.ConfigSyncConfig{
		AuthMode:    config.ConfigSyncAuthModeSigned,
		JWTIssuer:   testIssuer,
		JWTAudience: testAudience,
	}}, discardLogger(), nil)
	if err == nil {
		t.Fatal("expected error when signed mode has no shared secret")
	}
}

func authenticate(a tokenAuthenticator, bearer string) (string, error) {
	id, err := a.verify(bearer)
	return id.Scope, err
}

func instanceClaims(instanceID, jti string, iat int64) jwt.MapClaims {
	claims := jwt.MapClaims{
		"iss":         testIssuer,
		"aud":         testAudience,
		"scope":       instanceID,
		"instance_id": instanceID,
		"exp":         time.Now().Add(time.Hour).Unix(),
	}
	if jti != "" {
		claims["jti"] = jti
	}
	if iat != 0 {
		claims["iat"] = iat
	}
	return claims
}

func TestVerify_ClaimsExtraction(t *testing.T) {
	auth, err := newJWTAuthenticator(newSignedTestConfig(t))
	if err != nil {
		t.Fatalf("newJWTAuthenticator: %v", err)
	}
	iat := time.Now().Add(-time.Minute).Unix()

	id, err := auth.verify(mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "jti-1", iat)))
	if err != nil {
		t.Fatalf("verify instance token: %v", err)
	}
	want := configsyncrevocation.Identity{Scope: "gw-1", JTI: "jti-1", IssuedAt: iat, Signed: true, InstanceScoped: true}
	if id != want {
		t.Fatalf("identity = %+v, want %+v", id, want)
	}

	legacy, err := auth.verify(mint(t, testSecret, jwt.SigningMethodHS256, validClaims()))
	if err != nil {
		t.Fatalf("verify legacy token: %v", err)
	}
	if want := (configsyncrevocation.Identity{Scope: "org_1", Signed: true}); legacy != want {
		t.Fatalf("legacy identity = %+v, want %+v", legacy, want)
	}
}

func TestVerify_MissingOrMalformedClaimsAreZero(t *testing.T) {
	auth, err := newJWTAuthenticator(newSignedTestConfig(t))
	if err != nil {
		t.Fatalf("newJWTAuthenticator: %v", err)
	}
	cases := map[string]jwt.MapClaims{
		"no jti and no iat": instanceClaims("gw-1", "", 0),
		"jti not a string":  func() jwt.MapClaims { c := instanceClaims("gw-1", "", 0); c["jti"] = 42; return c }(),
		"negative iat":      instanceClaims("gw-1", "", -5),
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			id, err := auth.verify(mint(t, testSecret, jwt.SigningMethodHS256, claims))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if id.JTI != "" || id.IssuedAt != 0 {
				t.Fatalf("identity = %+v, want empty jti and zero iat", id)
			}
			if !id.Signed || !id.InstanceScoped || id.Scope != "gw-1" {
				t.Fatalf("identity = %+v, want a signed instance identity for gw-1", id)
			}
		})
	}
}

func TestVerify_SharedIsUnsigned(t *testing.T) {
	auth := newSharedAuthenticator(config.ConfigSyncConfig{Token: "tok"})
	id, err := auth.verify("tok")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id != (configsyncrevocation.Identity{}) {
		t.Fatalf("shared identity = %+v, want zero value", id)
	}
}

func TestVerify_CompositeKeepsJWTIdentity(t *testing.T) {
	cfg := newSignedTestConfig(t)
	cfg.AuthMode = config.ConfigSyncAuthModeComposite
	cfg.Token = "shared-tok"
	auth, err := newCompositeAuthenticator(cfg)
	if err != nil {
		t.Fatalf("newCompositeAuthenticator: %v", err)
	}
	id, err := auth.verify(mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "jti-1", 100)))
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}
	if !id.Signed || id.JTI != "jti-1" || id.Scope != "gw-1" {
		t.Fatalf("composite jwt identity = %+v", id)
	}
	shared, err := auth.verify("shared-tok")
	if err != nil {
		t.Fatalf("verify shared: %v", err)
	}
	if shared.Signed {
		t.Fatalf("composite shared identity = %+v, want unsigned", shared)
	}
}

// TestVerify_PreservesAcceptance pins the accept/reject decision and scope of every token kind.
func TestVerify_PreservesAcceptance(t *testing.T) {
	signed := newSignedTestConfig(t)
	signed.JWTSecret = "new-secret"
	signed.JWTSecretPrevious = testSecret
	composite := signed
	composite.AuthMode = config.ConfigSyncAuthModeComposite
	composite.Token = "shared-tok"
	composite.TokenPrevious = "old-shared-tok"

	jwtAuth, err := newJWTAuthenticator(signed)
	if err != nil {
		t.Fatalf("newJWTAuthenticator: %v", err)
	}
	compositeAuth, err := newCompositeAuthenticator(composite)
	if err != nil {
		t.Fatalf("newCompositeAuthenticator: %v", err)
	}
	sharedAuth := newSharedAuthenticator(composite)

	expired := instanceClaims("gw-1", "jti-1", 100)
	expired["exp"] = time.Now().Add(-time.Hour).Unix()

	tokens := map[string]string{
		"instance token":            mint(t, "new-secret", jwt.SigningMethodHS256, instanceClaims("gw-1", "jti-1", 100)),
		"instance token old secret": mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "jti-1", 100)),
		"instance token no jti iat": mint(t, "new-secret", jwt.SigningMethodHS256, instanceClaims("gw-1", "", 0)),
		"legacy scope token":        mint(t, "new-secret", jwt.SigningMethodHS256, validClaims()),
		"expired token":             mint(t, "new-secret", jwt.SigningMethodHS256, expired),
		"wrong secret":              mint(t, otherSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "jti-1", 100)),
		"shared token":              "shared-tok",
		"previous shared token":     "old-shared-tok",
		"garbage":                   "not-a-token",
		"empty":                     "",
	}
	type outcome struct {
		ok    bool
		scope string
	}
	expect := map[string]map[string]outcome{
		"jwt": {
			"instance token":            {true, "gw-1"},
			"instance token old secret": {true, "gw-1"},
			"instance token no jti iat": {true, "gw-1"},
			"legacy scope token":        {true, "org_1"},
		},
		"composite": {
			"instance token":            {true, "gw-1"},
			"instance token old secret": {true, "gw-1"},
			"instance token no jti iat": {true, "gw-1"},
			"legacy scope token":        {true, "org_1"},
			"shared token":              {true, ""},
			"previous shared token":     {true, ""},
		},
		"shared": {
			"shared token":          {true, ""},
			"previous shared token": {true, ""},
		},
	}
	authenticators := map[string]tokenAuthenticator{"jwt": jwtAuth, "composite": compositeAuth, "shared": sharedAuth}

	for authName, auth := range authenticators {
		for tokenName, token := range tokens {
			t.Run(authName+"/"+tokenName, func(t *testing.T) {
				want := expect[authName][tokenName]
				id, err := auth.verify(token)
				if (err == nil) != want.ok || id.Scope != want.scope {
					t.Fatalf("verify = (%+v, %v), want ok=%v scope=%q", id, err, want.ok, want.scope)
				}
			})
		}
	}
}
