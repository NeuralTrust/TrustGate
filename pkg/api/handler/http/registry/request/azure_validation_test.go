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

package request

import "testing"

func TestCreateRegistryRequest_ValidateAzureAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		auth    *AzureAuthRequest
		wantErr bool
	}{
		{name: "api key", auth: &AzureAuthRequest{Endpoint: "https://x", APIKey: "az-key"}},
		{name: "service principal", auth: &AzureAuthRequest{Endpoint: "https://x", ClientID: "client", ClientSecret: "secret", TenantID: "tenant"}},
		{name: "default azure credential", auth: &AzureAuthRequest{Endpoint: "https://x", UseManagedIdentity: true}},
		{name: "missing endpoint", auth: &AzureAuthRequest{APIKey: "az-key"}, wantErr: true},
		{name: "mixed modes", auth: &AzureAuthRequest{Endpoint: "https://x", APIKey: "az-key", UseManagedIdentity: true}, wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := CreateRegistryRequest{
				Name:     "azure",
				Provider: "azure",
				Auth: &TargetAuthRequest{
					Type:  "azure",
					Azure: tc.auth,
				},
			}

			err := req.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestTestConnectionRequest_ValidateAzureAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		auth    *AzureAuthRequest
		wantErr bool
	}{
		{name: "api key", auth: &AzureAuthRequest{Endpoint: "https://x", APIKey: "az-key"}},
		{name: "service principal", auth: &AzureAuthRequest{Endpoint: "https://x", ClientID: "client", ClientSecret: "secret", TenantID: "tenant"}},
		{name: "default azure credential", auth: &AzureAuthRequest{Endpoint: "https://x", UseManagedIdentity: true}},
		{name: "missing endpoint", auth: &AzureAuthRequest{APIKey: "az-key"}, wantErr: true},
		{name: "incomplete service principal", auth: &AzureAuthRequest{Endpoint: "https://x", ClientID: "client", ClientSecret: "secret"}, wantErr: true},
		{name: "mixed modes", auth: &AzureAuthRequest{Endpoint: "https://x", APIKey: "az-key", UseManagedIdentity: true}, wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := TestConnectionRequest{
				Provider: "azure",
				Auth: &TargetAuthRequest{
					Type:  "azure",
					Azure: tc.auth,
				},
			}

			err := req.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
