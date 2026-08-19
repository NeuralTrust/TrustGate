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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
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

func TestRepository_AuthEncryptionRoundTrip(t *testing.T) {
	t.Parallel()

	cipher, err := crypto.NewCipher("functional-test-secret-0123456789abcdef")
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	r := &Repository{cipher: cipher}

	const apiKey = "sk-super-secret-value"
	stored, err := r.encryptAuth(domain.NewAPIKeyAuth(apiKey))
	if err != nil {
		t.Fatalf("encryptAuth: %v", err)
	}
	ciphertext, ok := stored.(string)
	if !ok || ciphertext == "" {
		t.Fatalf("encryptAuth returned %T (%v), want non-empty string", stored, stored)
	}
	if strings.Contains(ciphertext, apiKey) {
		t.Fatalf("stored auth leaks the plaintext secret: %q", ciphertext)
	}

	provider := "openai"
	reg, err := r.scanRegistry(fakeRow{values: []any{
		ids.New[ids.RegistryKind](),
		ids.New[ids.GatewayKind](),
		"openai-pool",
		string(domain.TypeLLM),
		true,
		&provider,
		[]byte(nil),
		[]byte(ciphertext),
		"",
		[]byte(nil),
		[]byte(nil),
		time.Now().UTC(),
		time.Now().UTC(),
	}})
	if err != nil {
		t.Fatalf("scanRegistry: %v", err)
	}
	if reg.Auth() == nil || reg.Auth().APIKey == nil {
		t.Fatalf("decrypted auth lost data: %+v", reg.Auth())
	}
	if reg.Auth().APIKey.APIKey != apiKey {
		t.Fatalf("decrypted api key = %q, want %q", reg.Auth().APIKey.APIKey, apiKey)
	}
}

func TestRepository_AuthEncryption_NilAuthStoresNull(t *testing.T) {
	t.Parallel()

	cipher, err := crypto.NewCipher("functional-test-secret-0123456789abcdef")
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	r := &Repository{cipher: cipher}

	stored, err := r.encryptAuth(nil)
	if err != nil {
		t.Fatalf("encryptAuth(nil): %v", err)
	}
	if stored != nil {
		t.Fatalf("encryptAuth(nil) = %v, want nil", stored)
	}
}

type fakeRow struct {
	values []any
}

func (f fakeRow) Scan(dest ...any) error {
	if len(dest) != len(f.values) {
		return fmt.Errorf("fakeRow: got %d dest, have %d values", len(dest), len(f.values))
	}
	for i, d := range dest {
		switch dst := d.(type) {
		case *ids.RegistryID:
			*dst = f.values[i].(ids.RegistryID)
		case *ids.GatewayID:
			*dst = f.values[i].(ids.GatewayID)
		case *string:
			*dst = f.values[i].(string)
		case **string:
			*dst = f.values[i].(*string)
		case *bool:
			*dst = f.values[i].(bool)
		case *[]byte:
			*dst = f.values[i].([]byte)
		case *time.Time:
			*dst = f.values[i].(time.Time)
		default:
			return fmt.Errorf("fakeRow: unsupported dest type %T", d)
		}
	}
	return nil
}
