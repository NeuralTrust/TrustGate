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

package auth

import (
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestConfig_Validate_RejectsRedactedClientSecret(t *testing.T) {
	t.Parallel()
	cfg := Config{OAuth2: &OAuth2Config{
		Issuer:       "https://issuer.example.com",
		Audiences:    []string{"gateway"},
		JWKSURL:      "https://issuer.example.com/jwks",
		ClientSecret: secret.Redacted,
	}}
	if err := cfg.Validate(TypeOAuth2); err == nil {
		t.Fatal("Validate() = nil, want rejection of redaction placeholder")
	}
}

func TestConfig_ResolveSecretsFrom_KeepsOAuth2Secret(t *testing.T) {
	t.Parallel()
	prev := Config{OAuth2: &OAuth2Config{
		Issuer:       "https://issuer.example.com",
		Audiences:    []string{"gateway"},
		JWKSURL:      "https://issuer.example.com/jwks",
		ClientSecret: "stored-secret",
	}}
	next := Config{OAuth2: &OAuth2Config{
		Issuer:       "https://issuer.example.com",
		Audiences:    []string{"gateway"},
		JWKSURL:      "https://issuer.example.com/jwks",
		ClientSecret: secret.Mask("stored-secret"),
	}}
	next.ResolveSecretsFrom(prev)
	if next.OAuth2.ClientSecret != "stored-secret" {
		t.Fatalf("ClientSecret = %q, want stored value kept", next.OAuth2.ClientSecret)
	}
}

func TestNewAPIKeyAuth_GeneratesKey(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	a, err := NewAPIKeyAuth(gwID, "client-key", true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.ID.IsNil() {
		t.Fatal("expected generated id")
	}
	if a.GatewayID != gwID {
		t.Fatalf("expected gateway id %s, got %s", gwID, a.GatewayID)
	}
	if a.Type != TypeAPIKey {
		t.Fatalf("expected api_key type, got %s", a.Type)
	}
	if a.RawKey == "" {
		t.Fatal("expected a generated plaintext key")
	}
	if a.KeyHash != HashAPIKey(a.RawKey) {
		t.Fatal("KeyHash must be the hash of RawKey")
	}
	wantPrefix, wantSuffix := APIKeyPreview(a.RawKey)
	if a.KeyPrefix != wantPrefix || a.KeySuffix != wantSuffix {
		t.Fatalf("preview = %q…%q, want %q…%q", a.KeyPrefix, a.KeySuffix, wantPrefix, wantSuffix)
	}
	if a.CreatedAt.IsZero() || a.UpdatedAt.IsZero() {
		t.Fatal("expected timestamps to be set")
	}
}

func TestAPIKeyPreview(t *testing.T) {
	t.Parallel()
	prefix, suffix := APIKeyPreview("ag_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd")
	if prefix != "ag_ABCDE" || suffix != "abcd" {
		t.Fatalf("preview = %q…%q, want ag_ABCDE…abcd", prefix, suffix)
	}
	if p, s := APIKeyPreview("short"); p != "" || s != "" {
		t.Fatalf("short key preview = %q…%q, want empty", p, s)
	}
}

func TestNewAPIKeyAuth_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	_, err := NewAPIKeyAuth(ids.New[ids.GatewayKind](), "  ", true, nil)
	if !errors.Is(err, ErrInvalidName) {
		t.Fatalf("err = %v, want ErrInvalidName", err)
	}
}

func TestGenerateAPIKey_UniqueAndPrefixed(t *testing.T) {
	t.Parallel()
	k1, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	k2, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if k1 == k2 {
		t.Fatal("two generated keys must differ")
	}
	if len(k1) < len(apiKeyPrefix)+10 || k1[:len(apiKeyPrefix)] != apiKeyPrefix {
		t.Fatalf("generated key %q must carry the %q prefix", k1, apiKeyPrefix)
	}
}

func TestHashAPIKey_Deterministic(t *testing.T) {
	t.Parallel()
	h1 := HashAPIKey("ag_secret")
	h2 := HashAPIKey("ag_secret")
	if h1 != h2 {
		t.Fatal("hash must be deterministic")
	}
	if HashAPIKey("ag_a") == HashAPIKey("ag_b") {
		t.Fatal("different keys must hash differently")
	}
}

func TestHasAPIKeyPrefix(t *testing.T) {
	t.Parallel()
	if !HasAPIKeyPrefix("ag_secret") {
		t.Fatal("generated api keys must match the prefix")
	}
	if HasAPIKeyPrefix("eyJhbGciOiJIUzI1NiJ9.payload.sig") {
		t.Fatal("JWTs must not match the api-key prefix")
	}
	if HasAPIKeyPrefix("") {
		t.Fatal("empty string must not match the prefix")
	}
}

func TestNewAuth_Validation(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	tests := []struct {
		name      string
		gatewayID ids.GatewayID
		authName  string
		authType  Type
		config    Config
		wantErr   error
	}{
		{
			name:      "empty name",
			gatewayID: gwID,
			authName:  "  ",
			authType:  TypeAPIKey,
			config:    Config{},
			wantErr:   ErrInvalidName,
		},
		{
			name:      "nil gateway",
			gatewayID: ids.GatewayID{},
			authName:  "k",
			authType:  TypeAPIKey,
			config:    Config{},
			wantErr:   ErrInvalidGatewayID,
		},
		{
			name:      "invalid type",
			gatewayID: gwID,
			authName:  "k",
			authType:  Type("bogus"),
			config:    Config{},
			wantErr:   ErrInvalidType,
		},
		{
			name:      "api_key must not carry a config payload",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeAPIKey,
			config:    Config{OAuth2: &OAuth2Config{Issuer: "https://issuer", JWKSURL: "https://x/jwks"}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "oauth2 missing issuer",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeOAuth2,
			config:    Config{OAuth2: &OAuth2Config{JWKSURL: "https://x/jwks"}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "oauth2 missing jwks and introspection with non-URL issuer",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeOAuth2,
			config:    Config{OAuth2: &OAuth2Config{Issuer: "not-a-url", Audiences: []string{"gateway"}}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "oauth2 missing audiences",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeOAuth2,
			config:    Config{OAuth2: &OAuth2Config{Issuer: "https://issuer", JWKSURL: "https://x/jwks"}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "mtls missing ca_cert",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeMTLS,
			config:    Config{MTLS: &MTLSConfig{}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "idp missing key material",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeOIDC,
			config:    Config{OAuth2: &OAuth2Config{Issuer: "issuer-without-scheme", Audiences: []string{"gateway"}}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "idp rejects hs algorithms",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeOIDC,
			config: Config{OAuth2: &OAuth2Config{
				Issuer:     "https://issuer",
				Audiences:  []string{"gateway"},
				JWKSURL:    "https://issuer/.well-known/jwks.json",
				Algorithms: []string{"HS256"},
			}},
			wantErr: ErrInvalidConfig,
		},
		{
			name:      "oauth2 with extra mtls payload",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeOAuth2,
			config:    Config{OAuth2: &OAuth2Config{Issuer: "https://issuer", JWKSURL: "https://x/jwks"}, MTLS: &MTLSConfig{CACert: "pem"}},
			wantErr:   ErrInvalidConfig,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewAuth(tt.gatewayID, tt.authName, tt.authType, true, tt.config)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
			if !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("expected validation error wrapping, got %v", err)
			}
		})
	}
}

func TestNewAuth_ValidPerType(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	cases := map[string]struct {
		authType Type
		config   Config
	}{
		"api_key": {TypeAPIKey, Config{}},
		"oauth2": {TypeOAuth2, Config{OAuth2: &OAuth2Config{
			Issuer:    "https://issuer",
			Audiences: []string{"gateway"},
			JWKSURL:   "https://issuer/.well-known/jwks.json",
		}}},
		"oauth2 issuer-only (JWKS via OIDC discovery)": {TypeOAuth2, Config{OAuth2: &OAuth2Config{
			Issuer:    "https://login.microsoftonline.com/tenant-id/v2.0",
			Audiences: []string{"trustgate"},
		}}},
		"mtls": {TypeMTLS, Config{MTLS: &MTLSConfig{CACert: "-----BEGIN CERTIFICATE-----"}}},
		// The deprecated alias validates as oauth2 and is canonicalized on the
		// way in, so a caller still pinned to it keeps working.
		"oidc alias": {TypeOIDC, Config{OAuth2: &OAuth2Config{
			Issuer:     "https://issuer",
			Audiences:  []string{"gateway"},
			JWKSURL:    "https://issuer/.well-known/jwks.json",
			Algorithms: []string{"RS256"},
		}}},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewAuth(gwID, name, tc.authType, true, tc.config); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfig_ScanNil(t *testing.T) {
	t.Parallel()
	var c Config
	if err := c.Scan(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.OAuth2 != nil || c.MTLS != nil {
		t.Fatal("expected empty config after scanning nil")
	}
}

func TestConfig_ValueRoundTrip(t *testing.T) {
	t.Parallel()
	original := Config{OAuth2: &OAuth2Config{
		Issuer:    "https://issuer",
		Audiences: []string{"gateway"},
		JWKSURL:   "https://issuer/.well-known/jwks.json",
	}}
	v, err := original.Value()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, ok := v.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", v)
	}
	var got Config
	if err := got.Scan(raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.OAuth2 == nil || got.OAuth2.Issuer != original.OAuth2.Issuer {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestSetExpiry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()

	t.Run("refuses an expiry that has already passed", func(t *testing.T) {
		t.Parallel()
		a, err := NewAPIKeyAuth(gwID, "k", true, nil)
		if err != nil {
			t.Fatalf("NewAPIKeyAuth: %v", err)
		}
		past := time.Now().UTC().Add(-time.Minute)
		if err := a.SetExpiry(&past, time.Now().UTC()); !errors.Is(err, ErrExpiryInThePast) {
			t.Fatalf("err = %v, want ErrExpiryInThePast", err)
		}
	})

	t.Run("judges the expiry against the given clock", func(t *testing.T) {
		t.Parallel()
		a, err := NewAPIKeyAuth(gwID, "k", true, nil)
		if err != nil {
			t.Fatalf("NewAPIKeyAuth: %v", err)
		}
		now := time.Now().UTC().Add(48 * time.Hour)
		tomorrow := now.Add(-24 * time.Hour)
		if err := a.SetExpiry(&tomorrow, now); !errors.Is(err, ErrExpiryInThePast) {
			t.Fatalf("err = %v, want ErrExpiryInThePast against the given clock", err)
		}
	})

	t.Run("refuses an expiry on anything but an api key", func(t *testing.T) {
		t.Parallel()
		a, err := NewAuth(gwID, "idp", TypeOAuth2, true, Config{OAuth2: &OAuth2Config{
			Issuer:    "https://issuer.example.com",
			Audiences: []string{"gateway"},
			JWKSURL:   "https://issuer.example.com/jwks",
		}})
		if err != nil {
			t.Fatalf("NewAuth: %v", err)
		}
		future := time.Now().UTC().Add(time.Hour)
		if err := a.SetExpiry(&future, time.Now().UTC()); !errors.Is(err, ErrInvalidType) {
			t.Fatalf("err = %v, want ErrInvalidType", err)
		}
	})

	t.Run("clears the expiry with nil", func(t *testing.T) {
		t.Parallel()
		future := time.Now().UTC().Add(time.Hour)
		a, err := NewAPIKeyAuth(gwID, "k", true, &future)
		if err != nil {
			t.Fatalf("NewAPIKeyAuth: %v", err)
		}
		if a.ExpiresAt == nil {
			t.Fatal("expected the expiry to be stored")
		}
		if err := a.SetExpiry(nil, time.Now().UTC()); err != nil {
			t.Fatalf("SetExpiry(nil): %v", err)
		}
		if a.ExpiresAt != nil {
			t.Fatal("expected the expiry to be cleared")
		}
	})
}

func TestIsExpired(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	past, future := now.Add(-time.Second), now.Add(time.Second)

	// A key with no expiry is the default and never retires itself.
	if (&Auth{}).IsExpired(now) {
		t.Fatal("a key with no expiry must never read as expired")
	}
	if !(&Auth{ExpiresAt: &past}).IsExpired(now) {
		t.Fatal("a key past its expiry must read as expired")
	}
	if (&Auth{ExpiresAt: &future}).IsExpired(now) {
		t.Fatal("a key with time left must not read as expired")
	}
	// The instant itself counts as expired: "expires at 09:00" means it is no
	// good at 09:00.
	if !(&Auth{ExpiresAt: &now}).IsExpired(now) {
		t.Fatal("a key must be expired at its own expiry instant")
	}
}

func TestAcceptsAPIKey(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Second), now.Add(time.Hour)
	hash := HashAPIKey("ag_key")
	live := func() *Auth { return &Auth{Type: TypeAPIKey, Enabled: true, KeyHash: hash} }
	cases := map[string]struct {
		auth func() *Auth
		want bool
	}{
		"never expires":     {live, true},
		"expires later":     {func() *Auth { a := live(); a.ExpiresAt = &future; return a }, true},
		"expired":           {func() *Auth { a := live(); a.ExpiresAt = &past; return a }, false},
		"expires right now": {func() *Auth { a := live(); a.ExpiresAt = &now; return a }, false},
		"disabled":          {func() *Auth { a := live(); a.Enabled = false; return a }, false},
		"other hash":        {func() *Auth { a := live(); a.KeyHash = HashAPIKey("ag_other"); return a }, false},
		"not an api key":    {func() *Auth { a := live(); a.Type = TypeOAuth2; return a }, false},
		"nil auth":          {func() *Auth { return nil }, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tc.auth().AcceptsAPIKey(hash, now); got != tc.want {
				t.Fatalf("AcceptsAPIKey = %v, want %v", got, tc.want)
			}
		})
	}
}

// Rotating replaces the secret. It says nothing about the expiry, so a key with
// three weeks left keeps them unless the caller asks for something else.
func TestRotateAPIKey_KeepsTheExpiry(t *testing.T) {
	t.Parallel()
	future := time.Now().UTC().Add(72 * time.Hour)
	a, err := NewAPIKeyAuth(ids.New[ids.GatewayKind](), "k", true, &future)
	if err != nil {
		t.Fatalf("NewAPIKeyAuth: %v", err)
	}
	rotatedAt := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	if _, err := a.RotateAPIKey(rotatedAt); err != nil {
		t.Fatalf("RotateAPIKey: %v", err)
	}
	if a.ExpiresAt == nil || !a.ExpiresAt.Equal(future) {
		t.Fatalf("ExpiresAt = %v, want it untouched at %v", a.ExpiresAt, future)
	}
	if !a.UpdatedAt.Equal(rotatedAt) {
		t.Fatalf("UpdatedAt = %v, want the given clock %v", a.UpdatedAt, rotatedAt)
	}
}

func TestAuth_IsOwned(t *testing.T) {
	t.Parallel()
	if (&Auth{}).IsOwned() || !(&Auth{OwnerID: "alice"}).IsOwned() {
		t.Fatal("IsOwned() must be true only for an auth with an owner")
	}
	if !errors.Is(ErrOwnedKeyExists, commonerrors.ErrAlreadyExists) {
		t.Fatal("ErrOwnedKeyExists must answer as an already-exists conflict")
	}
}

func TestAuth_ManagedBy(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		owner, caller string
		want          error
	}{
		"admin on an application key":  {},
		"admin on an owned key":        {owner: "alice", want: ErrOwnedKey},
		"owner on their key":           {owner: "alice", caller: "alice"},
		"another user on an owned key": {owner: "alice", caller: "bob", want: ErrNotFound},
		"a user on an application key": {caller: "alice", want: ErrNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := (&Auth{OwnerID: tc.owner}).ManagedBy(tc.caller)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("ManagedBy(%q) on owner %q = %v, want %v", tc.caller, tc.owner, err, tc.want)
			}
		})
	}
	if !errors.Is(ErrOwnedKey, commonerrors.ErrManagedByOwner) {
		t.Fatal("ErrOwnedKey must answer as managed by its owner")
	}
}

func TestValidateOwnedExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		at   time.Time
		want error
	}{
		"zero":            {at: time.Time{}, want: ErrOwnedExpiry},
		"in the past":     {at: now.Add(-time.Hour), want: ErrOwnedExpiry},
		"now":             {at: now, want: ErrOwnedExpiry},
		"one second":      {at: now.Add(time.Second)},
		"exactly 90 days": {at: time.Date(2026, 12, 31, 12, 0, 0, 0, time.UTC)},
		"90 days and 1 s": {at: time.Date(2026, 12, 31, 12, 0, 1, 0, time.UTC), want: ErrOwnedExpiry},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := ValidateOwnedExpiry(tc.at, now)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("ValidateOwnedExpiry(%v) = %v, want %v", tc.at, err, tc.want)
			}
		})
	}
	if !errors.Is(ErrOwnedExpiry, commonerrors.ErrValidation) {
		t.Fatal("ErrOwnedExpiry must answer as a validation error")
	}
}

func TestNewOwnedAPIKeyAuth(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(30 * 24 * time.Hour)

	a, err := NewOwnedAPIKeyAuth(gwID, "alice", expiresAt, now)
	if err != nil {
		t.Fatalf("NewOwnedAPIKeyAuth: %v", err)
	}
	if !a.IsOwned() || a.OwnerID != "alice" || a.Name != "personal" || a.Type != TypeAPIKey || !a.Enabled || !a.ExpiresAt.Equal(expiresAt) || !a.CreatedAt.Equal(now) {
		t.Fatalf("auth = %+v, want an enabled api_key named personal, owned by alice, expiring at %v", a, expiresAt)
	}
	if a.RawKey == "" || a.KeyHash != HashAPIKey(a.RawKey) || a.KeyPrefix == "" || a.KeySuffix == "" {
		t.Fatal("an owned key must carry a fresh secret, its hash and its preview")
	}
	if _, err := NewOwnedAPIKeyAuth(gwID, " ", expiresAt, now); !errors.Is(err, ErrInvalidOwner) {
		t.Fatalf("blank owner: err = %v, want ErrInvalidOwner", err)
	}
	if ValidateOwner("") == nil || ValidateOwner("alice") != nil || !errors.Is(ErrInvalidOwner, commonerrors.ErrValidation) {
		t.Fatal("ValidateOwner must refuse only a blank owner, as a validation error")
	}
	if _, err := NewOwnedAPIKeyAuth(gwID, "alice", now.Add(MaxOwnedKeyLifetime+time.Second), now); !errors.Is(err, ErrOwnedExpiry) {
		t.Fatalf("expiry beyond the cap: err = %v, want ErrOwnedExpiry", err)
	}
}
