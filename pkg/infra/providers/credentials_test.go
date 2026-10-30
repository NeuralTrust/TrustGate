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
	"encoding/base64"
	"strings"
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

func TestCredentialsFromTargetAuth_GCPServiceAccount(t *testing.T) {
	t.Parallel()

	serviceAccount := `{"type":"service_account","client_email":"sa@proj.iam.gserviceaccount.com"}`
	empty := ""

	tests := []struct {
		name    string
		auth    *registry.TargetAuth
		wantSA  string
		wantNil bool
	}{
		{
			name:   "service account json is carried over",
			auth:   registry.NewGCPServiceAccountAuth(serviceAccount),
			wantSA: serviceAccount,
		},
		{
			name:    "empty payload yields no credentials",
			auth:    &registry.TargetAuth{Type: registry.AuthTypeGCPServiceAccount, GCPServiceAccount: &empty},
			wantNil: true,
		},
		{
			name:    "missing payload yields no credentials",
			auth:    &registry.TargetAuth{Type: registry.AuthTypeGCPServiceAccount},
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			creds := providers.CredentialsFromTargetAuth(tc.auth)
			if tc.wantNil {
				if creds.GCP != nil {
					t.Fatalf("GCP credentials = %+v, want nil", *creds.GCP)
				}
				return
			}
			if creds.GCP == nil {
				t.Fatal("GCP credentials are nil: the service account payload never reaches the provider client")
			}
			if creds.GCP.ServiceAccountJSON != tc.wantSA {
				t.Fatalf("ServiceAccountJSON = %q, want %q", creds.GCP.ServiceAccountJSON, tc.wantSA)
			}
		})
	}
}

func TestApplyIncomingBearer_Passthrough(t *testing.T) {
	t.Parallel()

	auth := &registry.TargetAuth{Type: registry.AuthTypePassthrough}
	creds := providers.CredentialsFromTargetAuth(auth)
	if creds.ApiKey != "" {
		t.Fatalf("stored passthrough ApiKey = %q, want empty", creds.ApiKey)
	}

	providers.ApplyIncomingBearer(&creds, auth, "Bearer ya29.caller-token")
	if creds.ApiKey != "ya29.caller-token" {
		t.Fatalf("passthrough ApiKey = %q, want caller token", creds.ApiKey)
	}
}

func TestApplyIncomingBearer_IgnoresStoredAuth(t *testing.T) {
	t.Parallel()

	auth := registry.NewAPIKeyAuth("sk-stored")
	creds := providers.CredentialsFromTargetAuth(auth)
	providers.ApplyIncomingBearer(&creds, auth, "Bearer ya29.caller-token")
	if creds.ApiKey != "sk-stored" {
		t.Fatalf("stored api_key was overwritten: %q", creds.ApiKey)
	}
}

func TestApplyIncomingBearer_ServiceAccountKey(t *testing.T) {
	t.Parallel()

	key := `{"type":"service_account","client_email":"sa@proj.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n"}`
	notServiceAccount := `{"type":"authorized_user","refresh_token":"x"}`
	b64 := base64.StdEncoding.EncodeToString

	tests := []struct {
		name          string
		authorization string
		wantGCP       string
		wantAPIKey    string
	}{
		{name: "raw json with bearer prefix", authorization: "Bearer " + key, wantGCP: key},
		{name: "raw json without prefix", authorization: key, wantGCP: key},
		{name: "base64 json with bearer prefix", authorization: "Bearer " + b64([]byte(key)), wantGCP: key},
		{name: "unpadded url-safe base64", authorization: "Bearer " + base64.RawURLEncoding.EncodeToString([]byte(key)), wantGCP: key},
		{name: "base64 of pretty-printed json", authorization: "Bearer " + b64([]byte("\n  "+key+"\n")), wantGCP: key},
		{name: "base64 json with an extra region field", authorization: "Bearer " + b64([]byte(`{"type":"service_account","region":"us-central1"}`)), wantGCP: `{"type":"service_account","region":"us-central1"}`},
		{name: "access token stays a bearer", authorization: "Bearer ya29.a0AfB_byC-token", wantAPIKey: "ya29.a0AfB_byC-token"},
		{name: "jwt stays a bearer", authorization: "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig", wantAPIKey: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig"},
		{name: "other json credential stays a bearer", authorization: "Bearer " + notServiceAccount, wantAPIKey: notServiceAccount},
		{name: "base64 of a non-key stays a bearer", authorization: "Bearer " + b64([]byte("opaque")), wantAPIKey: b64([]byte("opaque"))},
		{name: "oversized key stays a bearer", authorization: "Bearer {" + strings.Repeat(" ", 16<<10) + "}", wantAPIKey: "{" + strings.Repeat(" ", 16<<10) + "}"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			auth := &registry.TargetAuth{Type: registry.AuthTypePassthrough}
			creds := providers.CredentialsFromTargetAuth(auth)
			providers.ApplyIncomingBearer(&creds, auth, tc.authorization)

			if creds.ApiKey != tc.wantAPIKey {
				t.Fatalf("ApiKey = %.40q, want %.40q", creds.ApiKey, tc.wantAPIKey)
			}
			if tc.wantGCP == "" {
				if creds.GCP != nil {
					t.Fatal("GCP credentials set for a non service-account bearer")
				}
				return
			}
			if creds.GCP == nil || creds.GCP.ServiceAccountJSON != tc.wantGCP {
				t.Fatalf("GCP credentials = %+v, want the decoded key", creds.GCP)
			}
		})
	}
}

func TestApplyIncomingBearer_ServiceAccountKeyIgnoredOnStoredAuth(t *testing.T) {
	t.Parallel()

	auth := registry.NewGCPServiceAccountAuth(`{"type":"service_account","client_email":"stored@proj.iam.gserviceaccount.com"}`)
	creds := providers.CredentialsFromTargetAuth(auth)
	providers.ApplyIncomingBearer(&creds, auth, `Bearer {"type":"service_account","client_email":"caller@proj.iam.gserviceaccount.com"}`)
	if !strings.Contains(creds.GCP.ServiceAccountJSON, "stored@") {
		t.Fatal("a caller key replaced the registry's stored key")
	}
}
