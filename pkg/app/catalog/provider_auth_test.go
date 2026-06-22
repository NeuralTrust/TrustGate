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

package catalog

import (
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

func TestProviderAuthOptions_AzureVariants(t *testing.T) {
	t.Parallel()

	opts := ProviderAuthOptions(providers.ProviderAzure)
	if len(opts) != 3 {
		t.Fatalf("len(auth_types) = %d, want 3", len(opts))
	}

	variants := make(map[string]AuthTypeOption, len(opts))
	for _, opt := range opts {
		if opt.Type != "azure" {
			t.Fatalf("type = %q, want azure", opt.Type)
		}
		if opt.Variant == "" {
			t.Fatal("expected variant for azure auth option")
		}
		variants[opt.Variant] = opt
	}

	apiKey := variants["api_key"]
	if !fieldRequired(apiKey.Fields, "endpoint") || !fieldRequired(apiKey.Fields, "api_key") {
		t.Fatalf("api_key variant fields = %+v", apiKey.Fields)
	}
	if fieldPresent(apiKey.Fields, "tenant_id") || fieldPresent(apiKey.Fields, "use_managed_identity") {
		t.Fatalf("api_key variant must not expose other credential fields: %+v", apiKey.Fields)
	}

	servicePrincipal := variants["service_principal"]
	for _, key := range []string{"endpoint", "tenant_id", "client_id", "client_secret"} {
		if !fieldRequired(servicePrincipal.Fields, key) {
			t.Fatalf("service_principal missing required field %q: %+v", key, servicePrincipal.Fields)
		}
	}

	managedIdentity := variants["managed_identity"]
	if !fieldRequired(managedIdentity.Fields, "endpoint") || !fieldRequired(managedIdentity.Fields, "use_managed_identity") {
		t.Fatalf("managed_identity variant fields = %+v", managedIdentity.Fields)
	}
	if defaultVal, ok := fieldDefault(managedIdentity.Fields, "use_managed_identity"); !ok || defaultVal != true {
		t.Fatalf("use_managed_identity default = %#v, want true", defaultVal)
	}
}

func TestProviderAuthOptions_BedrockVariants(t *testing.T) {
	t.Parallel()

	opts := ProviderAuthOptions(providers.ProviderBedrock)
	if len(opts) != 2 {
		t.Fatalf("len(auth_types) = %d, want 2", len(opts))
	}

	variants := make(map[string]AuthTypeOption, len(opts))
	for _, opt := range opts {
		if opt.Type != "aws" {
			t.Fatalf("type = %q, want aws", opt.Type)
		}
		variants[opt.Variant] = opt
	}

	accessKey := variants["access_key"]
	for _, key := range []string{"region", "access_key_id", "secret_access_key"} {
		if !fieldRequired(accessKey.Fields, key) {
			t.Fatalf("access_key missing required field %q: %+v", key, accessKey.Fields)
		}
	}
	if fieldRequired(accessKey.Fields, "use_role") {
		t.Fatalf("access_key variant must not require use_role: %+v", accessKey.Fields)
	}

	assumeRole := variants["assume_role"]
	for _, key := range []string{"region", "access_key_id", "secret_access_key", "role", "use_role"} {
		if !fieldRequired(assumeRole.Fields, key) {
			t.Fatalf("assume_role missing required field %q: %+v", key, assumeRole.Fields)
		}
	}
	if defaultVal, ok := fieldDefault(assumeRole.Fields, "use_role"); !ok || defaultVal != true {
		t.Fatalf("use_role default = %#v, want true", defaultVal)
	}
}

func TestProviderAuthOptions_SimpleProvidersOmitVariant(t *testing.T) {
	t.Parallel()

	opts := ProviderAuthOptions(providers.ProviderOpenAI)
	if len(opts) != 1 {
		t.Fatalf("len(auth_types) = %d, want 1", len(opts))
	}

	raw, err := json.Marshal(opts[0])
	if err != nil {
		t.Fatalf("marshal auth option: %v", err)
	}
	if string(raw) != `{"type":"api_key","label":"API Key","fields":[{"key":"api_key","label":"API Key","type":"string","description":"Secret API key used to authenticate requests with the provider.","required":true,"secret":true}]}` {
		t.Fatalf("unexpected json: %s", raw)
	}
}

func TestProviderAuthOptions_OpenAICompatibleHeaderFields(t *testing.T) {
	t.Parallel()

	opts := ProviderAuthOptions(providers.ProviderOpenAICompatible)
	if len(opts) != 1 {
		t.Fatalf("len(auth_types) = %d, want 1", len(opts))
	}

	opt := opts[0]
	if opt.Type != "api_key" {
		t.Fatalf("type = %q, want api_key", opt.Type)
	}
	for _, key := range []string{"api_key", "header_name", "header_value"} {
		if !fieldPresent(opt.Fields, key) {
			t.Fatalf("missing field %q: %+v", key, opt.Fields)
		}
	}
	if fieldRequired(opt.Fields, "api_key") {
		t.Fatal("api_key must not be required when header auth is supported")
	}
}

func fieldRequired(fields []AuthField, key string) bool {
	for _, field := range fields {
		if field.Key == key {
			return field.Required
		}
	}
	return false
}

func fieldPresent(fields []AuthField, key string) bool {
	for _, field := range fields {
		if field.Key == key {
			return true
		}
	}
	return false
}

func fieldDefault(fields []AuthField, key string) (any, bool) {
	for _, field := range fields {
		if field.Key == key {
			return field.Default, true
		}
	}
	return nil, false
}
