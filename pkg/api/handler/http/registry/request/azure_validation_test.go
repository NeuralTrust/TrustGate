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
