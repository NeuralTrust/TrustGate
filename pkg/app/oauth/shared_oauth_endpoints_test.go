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

package oauth

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestApplySharedOAuth_OnlyForProviderEndpoints(t *testing.T) {
	t.Parallel()
	shared := mcpoauth.NewGoogleWorkspace("shared-id", "shared-secret")
	tests := []struct {
		name       string
		tokenURL   string
		wantSecret string
	}{
		{"provider token endpoint", "https://oauth2.googleapis.com/token", "shared-secret"},
		{"endpoints left to the catalog", "", "shared-secret"},
		{"another token endpoint", "https://idp.example.com/token", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &registrydomain.MCPAuth{
				Mode:     registrydomain.MCPAuthModeForwarded,
				Provider: mcpoauth.GmailCode,
				ClientID: "shared-id",
				TokenURL: tt.tokenURL,
			}
			if tt.tokenURL != "" {
				cfg.AuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
			}
			reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{Code: mcpoauth.GmailCode, Auth: cfg}}
			got := applySharedOAuth(cfg, reg, shared)
			if got.ClientSecret != tt.wantSecret {
				t.Fatalf("ClientSecret = %q, want %q", got.ClientSecret, tt.wantSecret)
			}
			if cfg.ClientSecret != "" {
				t.Fatal("the stored auth was modified")
			}
		})
	}
}
