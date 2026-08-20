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
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestOAuth2Config_Validate_SessionMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		config  OAuth2Config
		wantErr bool
	}{
		{
			name: "session mode with valid userinfo url",
			config: OAuth2Config{
				Issuer:      "https://github.com",
				Audiences:   []string{"gateway"},
				SessionMode: true,
				UserInfoURL: "https://api.github.com/user",
			},
			wantErr: false,
		},
		{
			name: "session mode with malformed userinfo url",
			config: OAuth2Config{
				Issuer:      "https://github.com",
				Audiences:   []string{"gateway"},
				SessionMode: true,
				UserInfoURL: "://api.github.com/user",
			},
			wantErr: true,
		},
		{
			name: "session mode without jwks introspection or http issuer passes",
			config: OAuth2Config{
				Issuer:      "github",
				Audiences:   []string{"gateway"},
				SessionMode: true,
			},
			wantErr: false,
		},
		{
			name: "off mode without jwks introspection or http issuer fails",
			config: OAuth2Config{
				Issuer:    "github",
				Audiences: []string{"gateway"},
			},
			wantErr: true,
		},
		{
			name: "off mode with jwks url unchanged",
			config: OAuth2Config{
				Issuer:    "https://issuer.example.com",
				Audiences: []string{"gateway"},
				JWKSURL:   "https://issuer.example.com/jwks",
			},
			wantErr: false,
		},
		{
			name: "empty subject claim is valid",
			config: OAuth2Config{
				Issuer:       "https://github.com",
				Audiences:    []string{"gateway"},
				SessionMode:  true,
				UserInfoURL:  "https://api.github.com/user",
				SubjectClaim: "",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := tt.config
			err := cfg.validate()
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("validate() error = %v, want ErrInvalidConfig", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate() error = %v, want nil", err)
			}
		})
	}
}

func TestOAuth2Config_Validate_KeyMaterial(t *testing.T) {
	t.Parallel()
	const pem = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"
	tests := []struct {
		name    string
		config  OAuth2Config
		wantErr string
	}{
		{
			name: "inline public keys satisfy the key material rule",
			config: OAuth2Config{
				Issuer:     "urn:example:idp",
				Audiences:  []string{"api"},
				PublicKeys: []string{pem},
			},
		},
		{
			name: "http issuer alone satisfies the key material rule",
			config: OAuth2Config{
				Issuer:    "https://login.microsoftonline.com/tenant-id/v2.0",
				Audiences: []string{"api"},
			},
		},
		{
			name: "introspection url alone satisfies the key material rule",
			config: OAuth2Config{
				Issuer:           "urn:example:idp",
				Audiences:        []string{"api"},
				IntrospectionURL: "https://issuer.example.com/introspect",
			},
		},
		{
			name: "jwks url and inline public keys together are accepted",
			config: OAuth2Config{
				Issuer:     "urn:example:idp",
				Audiences:  []string{"api"},
				JWKSURL:    "https://issuer.example.com/jwks",
				PublicKeys: []string{pem},
			},
		},
		{
			name: "no key material and a non http issuer is rejected",
			config: OAuth2Config{
				Issuer:    "urn:example:idp",
				Audiences: []string{"api"},
			},
			wantErr: "oauth2 requires jwks_url, introspection_url or public_keys, or an http(s) issuer for OIDC discovery",
		},
		{
			name: "blank public keys entries do not count as key material",
			config: OAuth2Config{
				Issuer:     "urn:example:idp",
				Audiences:  []string{"api"},
				PublicKeys: []string{"  "},
			},
			wantErr: "oauth2 requires jwks_url, introspection_url or public_keys, or an http(s) issuer for OIDC discovery",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := tt.config
			err := cfg.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("validate() error = %v, want ErrInvalidConfig", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestOAuth2Config_Validate_RejectsHMACAlgorithms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		algorithms []string
		wantErr    bool
	}{
		{name: "hs256", algorithms: []string{"HS256"}, wantErr: true},
		{name: "lowercase hs384 with padding", algorithms: []string{" hs384 "}, wantErr: true},
		{name: "hmac among asymmetric algorithms", algorithms: []string{"RS256", "HS512"}, wantErr: true},
		{name: "asymmetric only", algorithms: []string{"RS256", "ES256"}},
		{name: "empty allowlist", algorithms: nil},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := OAuth2Config{
				Issuer:     "https://issuer.example.com",
				Audiences:  []string{"gateway"},
				JWKSURL:    "https://issuer.example.com/jwks",
				Algorithms: tt.algorithms,
			}
			err := cfg.validate()
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("validate() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("validate() error = %v, want ErrInvalidConfig", err)
			}
			const want = "oauth2.allowed_algorithms must not include HMAC algorithms"
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("validate() error = %q, want it to contain %q", err.Error(), want)
			}
		})
	}
}

func TestOAuth2Config_Validate_ManualAuthorizationEndpoints(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		config  OAuth2Config
		wantErr bool
	}{
		{
			name: "github session mode with explicit endpoints and client id",
			config: OAuth2Config{
				Issuer:       "https://github.com",
				Audiences:    []string{"gateway"},
				ClientID:     "gh-client",
				ClientSecret: "gh-secret",
				SessionMode:  true,
				UserInfoURL:  "https://api.github.com/user",
				AuthorizeURL: "https://github.com/login/oauth/authorize",
				TokenURL:     "https://github.com/login/oauth/access_token",
			},
			wantErr: false,
		},
		{
			name: "authorize url without token url",
			config: OAuth2Config{
				Issuer:       "https://github.com",
				Audiences:    []string{"gateway"},
				ClientID:     "gh-client",
				SessionMode:  true,
				AuthorizeURL: "https://github.com/login/oauth/authorize",
			},
			wantErr: true,
		},
		{
			name: "explicit endpoints without client id",
			config: OAuth2Config{
				Issuer:       "https://github.com",
				Audiences:    []string{"gateway"},
				SessionMode:  true,
				AuthorizeURL: "https://github.com/login/oauth/authorize",
				TokenURL:     "https://github.com/login/oauth/access_token",
			},
			wantErr: true,
		},
		{
			name: "malformed authorize url",
			config: OAuth2Config{
				Issuer:       "https://github.com",
				Audiences:    []string{"gateway"},
				ClientID:     "gh-client",
				SessionMode:  true,
				AuthorizeURL: "://github.com/login/oauth/authorize",
				TokenURL:     "https://github.com/login/oauth/access_token",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := tt.config
			err := cfg.validate()
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("validate() error = %v, want ErrInvalidConfig", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate() error = %v, want nil", err)
			}
		})
	}
}

func TestOAuth2Config_CanBrokerLogin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config *OAuth2Config
		want   bool
	}{
		{
			name: "client id with explicit endpoints",
			config: &OAuth2Config{
				ClientID:     "gw-client",
				Issuer:       "urn:example:idp",
				AuthorizeURL: "https://idp.example.com/authorize",
				TokenURL:     "https://idp.example.com/token",
			},
			want: true,
		},
		{
			name:   "client id with discoverable http issuer",
			config: &OAuth2Config{ClientID: "gw-client", Issuer: "https://idp.example.com"},
			want:   true,
		},
		{
			name:   "client id with non http issuer and no endpoints",
			config: &OAuth2Config{ClientID: "gw-client", Issuer: "urn:example:idp"},
		},
		{
			name:   "blank client id with http issuer",
			config: &OAuth2Config{Issuer: "https://idp.example.com"},
		},
		{
			name:   "whitespace client id is blank",
			config: &OAuth2Config{ClientID: "   ", Issuer: "https://idp.example.com"},
		},
		{
			name:   "issuer without host is not discoverable",
			config: &OAuth2Config{ClientID: "gw-client", Issuer: "https://"},
		},
		{
			name:   "only one endpoint falls back to the issuer",
			config: &OAuth2Config{ClientID: "gw-client", Issuer: "urn:example:idp", TokenURL: "https://idp.example.com/token"},
		},
		{name: "nil config"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.config.CanBrokerLogin(); got != tt.want {
				t.Fatalf("CanBrokerLogin() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestNormalizeType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   Type
		want Type
	}{
		{name: "legacy oidc becomes oauth2", in: TypeOIDC, want: TypeOAuth2},
		{name: "oauth2 is unchanged", in: TypeOAuth2, want: TypeOAuth2},
		{name: "api key is unchanged", in: TypeAPIKey, want: TypeAPIKey},
		{name: "mtls is unchanged", in: TypeMTLS, want: TypeMTLS},
		{name: "unknown type is unchanged", in: Type("bogus"), want: Type("bogus")},
		{name: "empty type is unchanged", in: Type(""), want: Type("")},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeType(tt.in); got != tt.want {
				t.Fatalf("NormalizeType(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestStoredTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   Type
		want []Type
	}{
		{name: "oauth2 covers its deprecated alias", in: TypeOAuth2, want: []Type{TypeOAuth2, TypeOIDC}},
		{name: "the alias resolves to the same set", in: TypeOIDC, want: []Type{TypeOAuth2, TypeOIDC}},
		{name: "api key covers only itself", in: TypeAPIKey, want: []Type{TypeAPIKey}},
		{name: "mtls covers only itself", in: TypeMTLS, want: []Type{TypeMTLS}},
		{name: "unknown type covers only itself", in: Type("bogus"), want: []Type{Type("bogus")}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := StoredTypes(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("StoredTypes(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("StoredTypes(%q) = %v, want %v", tt.in, got, tt.want)
				}
			}
		})
	}
}

func TestStoredTypesCoversEveryTypeThatNormalizesOntoIt(t *testing.T) {
	t.Parallel()
	for _, canonical := range Types() {
		canonical := canonical
		t.Run(string(canonical), func(t *testing.T) {
			t.Parallel()
			stored := StoredTypes(canonical)
			for _, candidate := range Types() {
				if NormalizeType(candidate) != NormalizeType(canonical) {
					continue
				}
				found := false
				for _, s := range stored {
					if s == candidate {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("StoredTypes(%q) = %v, missing %q which normalizes onto it",
						canonical, stored, candidate)
				}
			}
		})
	}
}

func TestConfig_UnmarshalJSON(t *testing.T) {
	t.Parallel()
	const pem = "-----BEGIN PUBLIC KEY-----"
	tests := []struct {
		name       string
		payload    string
		wantErr    bool
		wantOAuth2 *OAuth2Config
		wantMTLS   *MTLSConfig
	}{
		{
			name:       "native oauth2 payload",
			payload:    `{"oauth2":{"issuer":"https://issuer.example.com","audiences":["gateway"],"jwks_url":"https://issuer.example.com/jwks"}}`,
			wantOAuth2: &OAuth2Config{Issuer: "https://issuer.example.com", Audiences: []string{"gateway"}, JWKSURL: "https://issuer.example.com/jwks"},
		},
		{
			name:       "legacy oidc payload lands under oauth2",
			payload:    `{"oidc":{"issuer":"https://issuer.example.com","audiences":["gateway"],"jwks_url":"https://issuer.example.com/jwks"}}`,
			wantOAuth2: &OAuth2Config{Issuer: "https://issuer.example.com", Audiences: []string{"gateway"}, JWKSURL: "https://issuer.example.com/jwks"},
		},
		{
			name: "legacy oidc payload carries every shared key",
			payload: `{"oidc":{"issuer":"https://issuer.example.com","audiences":["gateway"],` +
				`"jwks_url":"https://issuer.example.com/jwks","public_keys":["` + pem + `"],` +
				`"required_scopes":["api.read"],"allowed_algorithms":["RS256"],"subject_claim":"oid"}}`,
			wantOAuth2: &OAuth2Config{
				Issuer:         "https://issuer.example.com",
				Audiences:      []string{"gateway"},
				JWKSURL:        "https://issuer.example.com/jwks",
				PublicKeys:     []string{pem},
				RequiredScopes: []string{"api.read"},
				Algorithms:     []string{"RS256"},
				SubjectClaim:   "oid",
			},
		},
		{
			name:       "both payloads keep the native one",
			payload:    `{"oauth2":{"issuer":"https://native.example.com"},"oidc":{"issuer":"https://legacy.example.com"}}`,
			wantOAuth2: &OAuth2Config{Issuer: "https://native.example.com"},
		},
		{
			name:     "mtls payload is untouched",
			payload:  `{"mtls":{"ca_cert":"pem"}}`,
			wantMTLS: &MTLSConfig{CACert: "pem"},
		},
		{
			name:    "empty object yields no payload",
			payload: `{}`,
		},
		{
			name:    "explicit null oidc payload yields no payload",
			payload: `{"oidc":null}`,
		},
		{
			name:    "malformed legacy payload is an error",
			payload: `{"oidc":{"audiences":"gateway"}}`,
			wantErr: true,
		},
		{
			name:    "malformed config is an error",
			payload: `[]`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got Config
			err := json.Unmarshal([]byte(tt.payload), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Unmarshal(%s) = nil error, want failure", tt.payload)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal(%s): %v", tt.payload, err)
			}
			if got.OIDC != nil {
				t.Fatalf("Unmarshal(%s) left a legacy payload behind: %+v", tt.payload, got.OIDC)
			}
			if !reflect.DeepEqual(got.OAuth2, tt.wantOAuth2) {
				t.Fatalf("Unmarshal(%s) oauth2 = %+v, want %+v", tt.payload, got.OAuth2, tt.wantOAuth2)
			}
			if !reflect.DeepEqual(got.MTLS, tt.wantMTLS) {
				t.Fatalf("Unmarshal(%s) mtls = %+v, want %+v", tt.payload, got.MTLS, tt.wantMTLS)
			}
		})
	}
}

func TestLegacyAliasProducesTheSamePersistedAuthAsOAuth2(t *testing.T) {
	t.Parallel()
	const fields = `"issuer":"https://issuer.example.com","audiences":["gateway"],` +
		`"jwks_url":"https://issuer.example.com/jwks","public_keys":["-----BEGIN PUBLIC KEY-----"],` +
		`"required_scopes":["api.read"],"allowed_algorithms":["RS256"],"subject_claim":"oid"`

	gatewayID := ids.New[ids.GatewayKind]()
	legacy := decodeConfig(t, `{"oidc":{`+fields+`}}`)
	native := decodeConfig(t, `{"oauth2":{`+fields+`}}`)

	legacyAuth, err := NewAuth(gatewayID, "idp", NormalizeType(TypeOIDC), true, legacy)
	if err != nil {
		t.Fatalf("NewAuth from the legacy alias: %v", err)
	}
	nativeAuth, err := NewAuth(gatewayID, "idp", NormalizeType(TypeOAuth2), true, native)
	if err != nil {
		t.Fatalf("NewAuth from the native payload: %v", err)
	}

	if legacyAuth.Type != nativeAuth.Type {
		t.Fatalf("persisted type = %q, want %q", legacyAuth.Type, nativeAuth.Type)
	}
	if legacyAuth.Type != TypeOAuth2 {
		t.Fatalf("persisted type = %q, want %q", legacyAuth.Type, TypeOAuth2)
	}
	legacyRaw, err := json.Marshal(legacyAuth.Config)
	if err != nil {
		t.Fatalf("marshal legacy config: %v", err)
	}
	nativeRaw, err := json.Marshal(nativeAuth.Config)
	if err != nil {
		t.Fatalf("marshal native config: %v", err)
	}
	if string(legacyRaw) != string(nativeRaw) {
		t.Fatalf("persisted config = %s, want %s", legacyRaw, nativeRaw)
	}
}

func TestLegacyAliasNarrowsProtocolScopes(t *testing.T) {
	t.Parallel()
	cfg := decodeConfig(t, `{"oidc":{"issuer":"https://issuer.example.com","audiences":["gateway"],`+
		`"jwks_url":"https://issuer.example.com/jwks","required_scopes":["openid"]}}`)

	err := cfg.Validate(NormalizeType(TypeOIDC))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Validate() error = %v, want ErrInvalidConfig", err)
	}
	const want = `oauth2.required_scopes cannot contain the OIDC protocol scope "openid"`
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate() error = %q, want it to contain %q", err.Error(), want)
	}
}

func decodeConfig(t *testing.T, payload string) Config {
	t.Helper()
	var cfg Config
	if err := json.Unmarshal([]byte(payload), &cfg); err != nil {
		t.Fatalf("unmarshal %s: %v", payload, err)
	}
	return cfg
}
