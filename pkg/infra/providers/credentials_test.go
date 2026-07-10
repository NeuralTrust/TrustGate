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

package providers_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

func TestCredentialsFromTargetAuth_Azure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		auth      *registry.TargetAuth
		wantKey   string
		wantAzure providers.Azure
	}{
		{
			name:    "api key",
			auth:    &registry.TargetAuth{Type: registry.AuthTypeAzure, Azure: &registry.AzureAuth{Endpoint: "https://x", Version: "2025-01-01", APIKey: "az-key"}},
			wantKey: "az-key",
			wantAzure: providers.Azure{
				Endpoint:   "https://x",
				ApiVersion: "2025-01-01",
				AuthMode:   providers.AzureAuthModeAPIKey,
			},
		},
		{
			name: "service principal",
			auth: &registry.TargetAuth{Type: registry.AuthTypeAzure, Azure: &registry.AzureAuth{
				Endpoint:     "https://x",
				Version:      "2025-01-01",
				ClientID:     "client",
				ClientSecret: "secret",
				TenantID:     "tenant",
			}},
			wantAzure: providers.Azure{
				Endpoint:     "https://x",
				ApiVersion:   "2025-01-01",
				AuthMode:     providers.AzureAuthModeServicePrincipal,
				ClientID:     "client",
				ClientSecret: "secret",
				TenantID:     "tenant",
			},
		},
		{
			name: "default azure credential",
			auth: &registry.TargetAuth{Type: registry.AuthTypeAzure, Azure: &registry.AzureAuth{
				Endpoint:           "https://x",
				Version:            "2025-01-01",
				UseManagedIdentity: true,
			}},
			wantAzure: providers.Azure{
				Endpoint:    "https://x",
				ApiVersion:  "2025-01-01",
				AuthMode:    providers.AzureAuthModeDefaultAzureCredential,
				UseIdentity: true,
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			creds := providers.CredentialsFromTargetAuth(tc.auth)
			if creds.ApiKey != tc.wantKey {
				t.Fatalf("ApiKey = %q, want %q", creds.ApiKey, tc.wantKey)
			}
			if creds.Azure == nil {
				t.Fatal("Azure credentials are nil")
			}
			if *creds.Azure != tc.wantAzure {
				t.Fatalf("Azure credentials = %+v, want %+v", *creds.Azure, tc.wantAzure)
			}
		})
	}
}
