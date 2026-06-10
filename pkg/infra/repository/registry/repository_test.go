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
