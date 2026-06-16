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

package registry

import (
	"encoding/json"
	"testing"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

func TestMarshalAuth_PreservesAzureFieldsByMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		auth *domain.TargetAuth
		want domain.AzureAuth
	}{
		{
			name: "api key",
			auth: &domain.TargetAuth{
				Type: domain.AuthTypeAzure,
				Azure: &domain.AzureAuth{
					Endpoint: "https://example.openai.azure.com",
					Version:  "2024-02-15-preview",
					APIKey:   "azure-api-key",
				},
			},
			want: domain.AzureAuth{
				Endpoint: "https://example.openai.azure.com",
				Version:  "2024-02-15-preview",
				APIKey:   "azure-api-key",
			},
		},
		{
			name: "service principal",
			auth: &domain.TargetAuth{
				Type: domain.AuthTypeAzure,
				Azure: &domain.AzureAuth{
					Endpoint:     "https://example.openai.azure.com",
					Version:      "2024-02-15-preview",
					ClientID:     "client-1",
					ClientSecret: "azure-client-secret",
					TenantID:     "tenant-1",
				},
			},
			want: domain.AzureAuth{
				Endpoint:     "https://example.openai.azure.com",
				Version:      "2024-02-15-preview",
				ClientID:     "client-1",
				ClientSecret: "azure-client-secret",
				TenantID:     "tenant-1",
			},
		},
		{
			name: "default azure credential",
			auth: &domain.TargetAuth{
				Type: domain.AuthTypeAzure,
				Azure: &domain.AzureAuth{
					Endpoint:           "https://example.openai.azure.com",
					Version:            "2024-02-15-preview",
					UseManagedIdentity: true,
				},
			},
			want: domain.AzureAuth{
				Endpoint:           "https://example.openai.azure.com",
				Version:            "2024-02-15-preview",
				UseManagedIdentity: true,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := marshalAuth(tt.auth)
			if err != nil {
				t.Fatalf("marshalAuth error: %v", err)
			}

			var got domain.TargetAuth
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal auth error: %v", err)
			}
			if got.Azure == nil {
				t.Fatal("Azure auth is nil")
			}
			if *got.Azure != tt.want {
				t.Fatalf("Azure auth = %+v, want %+v", *got.Azure, tt.want)
			}
		})
	}
}
