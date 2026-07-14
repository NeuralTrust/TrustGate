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
	scope, err := auth.authenticate(mint(t, testSecret, jwt.SigningMethodHS256, validClaims()))
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
		scope, err := auth.authenticate(mint(t, secret, jwt.SigningMethodHS256, validClaims()))
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
			if _, err := auth.authenticate(token); err == nil {
				t.Fatalf("expected rejection for %s", name)
			}
		})
	}
}

func TestSharedAuthenticator(t *testing.T) {
	auth := newSharedAuthenticator(config.ConfigSyncConfig{Token: "tok", TokenPrevious: "old"})
	for _, tok := range []string{"tok", "old"} {
		scope, err := auth.authenticate(tok)
		if err != nil {
			t.Fatalf("authenticate(%q): %v", tok, err)
		}
		if scope != "" {
			t.Fatalf("shared scope = %q, want empty", scope)
		}
	}
	if _, err := auth.authenticate("wrong"); err == nil {
		t.Fatal("expected rejection for wrong token")
	}
	unconfigured := newSharedAuthenticator(config.ConfigSyncConfig{})
	if _, err := unconfigured.authenticate("anything"); err == nil {
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

	scope, err := auth.authenticate(mint(t, testSecret, jwt.SigningMethodHS256, validClaims()))
	if err != nil {
		t.Fatalf("jwt authenticate: %v", err)
	}
	if scope != "org_1" {
		t.Fatalf("jwt scope = %q, want org_1", scope)
	}

	for _, tok := range []string{"shared-tok", "old-tok"} {
		scope, err := auth.authenticate(tok)
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
			if _, err := auth.authenticate(bearer); err == nil {
				t.Fatalf("expected rejection for %s", name)
			}
		})
	}
}

func TestNewAuthInterceptor_Composite(t *testing.T) {
	cfg := newSignedTestConfig(t)
	cfg.AuthMode = config.ConfigSyncAuthModeComposite
	cfg.Token = "shared-tok"
	interceptor, err := NewAuthInterceptor(&config.Config{ConfigSync: cfg}, discardLogger())
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
	}}, discardLogger())
	if err == nil {
		t.Fatal("expected error when signed mode has no shared secret")
	}
}
