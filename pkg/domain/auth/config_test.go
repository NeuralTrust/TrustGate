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
