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
	"slices"
	"strings"
	"testing"
)

func TestOAuth2Config_Validate_LoginScopes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		clientID    string
		sessionMode bool
		scopes      []string
		want        []string
		wantErr     string
	}{
		{name: "none", clientID: "app-1"},
		{name: "entra pair", clientID: "app-1", scopes: []string{"api://gw/mcp.access", "offline_access"}, want: []string{"api://gw/mcp.access", "offline_access"}},
		{name: "trims entries", clientID: "app-1", scopes: []string{" api://gw/mcp.access ", "\toffline_access\n"}, want: []string{"api://gw/mcp.access", "offline_access"}},
		{name: "duplicates collapsed", clientID: "app-1", scopes: []string{"offline_access", " api://gw/mcp.access", "offline_access ", "api://gw/mcp.access"}, want: []string{"offline_access", "api://gw/mcp.access"}},
		{name: "empty entry", clientID: "app-1", scopes: []string{"api://gw/mcp.access", "  "}, wantErr: "login_scopes"},
		{name: "inner whitespace", clientID: "app-1", scopes: []string{"api://gw/mcp.access offline_access"}, wantErr: "login_scopes"},
		{name: "no client_id", scopes: []string{"api://gw/mcp.access"}, wantErr: "client_id"},
		{name: "protocol scopes allowed", clientID: "app-1", scopes: []string{"openid", "profile", "offline_access"}, want: []string{"openid", "profile", "offline_access"}},
		{name: "session mode allowed", clientID: "app-1", sessionMode: true, scopes: []string{"offline_access"}, want: []string{"offline_access"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := entraValidateOnly()
			cfg.ClientID = tc.clientID
			cfg.SessionMode = tc.sessionMode
			cfg.LoginScopes = slices.Clone(tc.scopes)

			err := cfg.validate()
			if tc.wantErr != "" {
				if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("validate() = %v, want ErrInvalidConfig naming %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate() = %v", err)
			}
			if !slices.Equal(cfg.LoginScopes, tc.want) {
				t.Fatalf("LoginScopes = %q, want %q", cfg.LoginScopes, tc.want)
			}
		})
	}
}

func TestOAuth2Config_LoginScopesDoNotChangeInteractive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  OAuth2Config
	}{
		{"validate only", OAuth2Config{Issuer: "https://login.microsoftonline.com/tid/v2.0"}},
		{"login client", OAuth2Config{Issuer: "https://login.microsoftonline.com/tid/v2.0", ClientID: "app-1"}},
		{"login client without endpoints", OAuth2Config{Issuer: "urn:entra", ClientID: "app-1"}},
		{"exchange client", OAuth2Config{Issuer: "https://login.microsoftonline.com/tid/v2.0", ExchangeClientID: "gw-app"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			withScopes := tc.cfg
			withScopes.LoginScopes = []string{"api://gw/mcp.access", "offline_access"}
			if got, want := withScopes.Interactive(), tc.cfg.Interactive(); got != want {
				t.Fatalf("Interactive() with login scopes = %v, want %v", got, want)
			}
		})
	}
}
