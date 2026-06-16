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

package response

import (
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

func TestFromAuth_MasksAzureSecretsAndReturnsIdentifiers(t *testing.T) {
	t.Parallel()
	got := FromAuth(&domain.TargetAuth{
		Type: domain.AuthTypeAzure,
		Azure: &domain.AzureAuth{
			Endpoint:     "https://example.openai.azure.com",
			Version:      "2024-02-15-preview",
			APIKey:       "azure-api-key-1234",
			ClientID:     "client-1",
			ClientSecret: "azure-client-secret-5678",
			TenantID:     "tenant-1",
		},
	})

	if got == nil || got.Azure == nil {
		t.Fatal("Azure response is nil")
	}
	if got.Azure.APIKey != secret.Redacted+"1234" {
		t.Fatalf("Azure APIKey = %q, want masked tail", got.Azure.APIKey)
	}
	if got.Azure.ClientSecret != secret.Redacted+"5678" {
		t.Fatalf("Azure ClientSecret = %q, want masked tail", got.Azure.ClientSecret)
	}
	if got.Azure.ClientID != "client-1" {
		t.Fatalf("Azure ClientID = %q, want client-1", got.Azure.ClientID)
	}
	if got.Azure.TenantID != "tenant-1" {
		t.Fatalf("Azure TenantID = %q, want tenant-1", got.Azure.TenantID)
	}
}
