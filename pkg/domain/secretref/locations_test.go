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

package secretref_test

import (
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/auth"

	"github.com/NeuralTrust/TrustGate/pkg/domain/consumer"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

func ptr[T any](v T) *T { return &v }

func populatedRegistry() *registry.Registry {
	return &registry.Registry{
		LLMTarget: &registry.LLMTarget{
			Provider:        "openai",
			ProviderOptions: map[string]any{"headers": map[string]any{"X-Api-Key": "v"}},
			Auth: &registry.TargetAuth{
				APIKey: &registry.APIKeyAuth{APIKey: "v", HeaderValue: "v", ParamValue: "v"},
				AWS:    &registry.AWSAuth{AccessKeyID: "v", SecretAccessKey: "v", SessionToken: "v"},
				Azure:  &registry.AzureAuth{APIKey: "v", ClientSecret: "v"},
				OAuth:  &registry.TargetOAuthConfig{ClientSecret: "v", RefreshToken: "v", Password: "v"},

				GCPServiceAccount: ptr("v"),
			},
		},
		MCPTarget: &registry.MCPTarget{
			Headers: map[string]string{"X-Token": "v"},
			Auth:    &registry.MCPAuth{Value: "v", ClientSecret: "v"},
		},
		A2ATarget: &registry.A2ATarget{
			Headers: map[string]string{"X-Token": "v"},
			Auth:    &registry.MCPAuth{Value: "v", ClientSecret: "v"},
		},
	}
}

func stringLeaves(t *testing.T, v any) [][]string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var leaves [][]string
	var walk func(node any, path []string)
	walk = func(node any, path []string) {
		switch n := node.(type) {
		case map[string]any:
			for k, child := range n {
				walk(child, append(append([]string(nil), path...), k))
			}
		case string:
			leaves = append(leaves, path)
		}
	}
	walk(doc, nil)
	return leaves
}

// TestRegistryLocationsExist fails when a declared location no longer matches
// the registry's JSON encoding, so a renamed field cannot silently stop being
// resolved.
func TestRegistryLocationsExist(t *testing.T) {
	t.Parallel()
	leaves := stringLeaves(t, populatedRegistry())
	for _, l := range secretref.Locations {
		if l.Entity != secretref.EntityRegistry {
			continue
		}
		found := false
		for _, leaf := range leaves {
			if l.Matches(secretref.EntityRegistry, leaf) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("location %s matches no field of an encoded registry", l)
		}
	}
}

func TestIsLocation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path []string
		want bool
	}{
		{[]string{"llm_target", "auth", "api_key", "api_key"}, true},
		{[]string{"llm_target", "provider_options", "headers", "X-Weird.Name"}, true},
		{[]string{"mcp_target", "headers", "Authorization"}, true},
		{[]string{"llm_target", "auth", "api_key", "header_name"}, false},
		{[]string{"llm_target", "provider_options", "base_url"}, false},
		{[]string{"llm_target", "provider_options", "headers"}, false},
		{[]string{"mcp_target", "url"}, false},
		{[]string{"name"}, false},
	}
	for _, tt := range tests {
		if got := secretref.IsLocation(secretref.EntityRegistry, tt.path); got != tt.want {
			t.Errorf("IsLocation(%v) = %v, want %v", tt.path, got, tt.want)
		}
	}
	if secretref.IsLocation("policy", []string{"llm_target", "auth", "api_key", "api_key"}) {
		t.Error("a location must only match its own entity")
	}
}

// TestConsumerLocationsExist is TestRegistryLocationsExist for consumers.
func TestConsumerLocationsExist(t *testing.T) {
	t.Parallel()
	c := consumer.Consumer{LBConfig: &consumer.LBConfig{EmbeddingConfig: &registry.EmbeddingConfig{
		Auth: &registry.APIKeyAuth{APIKey: "v", HeaderValue: "v"},
	}}}
	leaves := stringLeaves(t, c)
	for _, l := range secretref.Locations {
		if l.Entity != secretref.EntityConsumer {
			continue
		}
		found := false
		for _, leaf := range leaves {
			if l.Matches(secretref.EntityConsumer, leaf) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("location %s matches no field of an encoded consumer", l)
		}
	}
}

// TestAuthLocationsExist is TestRegistryLocationsExist for auths.
func TestAuthLocationsExist(t *testing.T) {
	t.Parallel()
	a := auth.Auth{Config: auth.Config{OAuth2: &auth.OAuth2Config{ClientSecret: "v", ExchangeClientSecret: "v"}}}
	leaves := stringLeaves(t, a)
	for _, l := range secretref.Locations {
		if l.Entity != secretref.EntityAuth {
			continue
		}
		found := false
		for _, leaf := range leaves {
			if l.Matches(secretref.EntityAuth, leaf) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("location %s matches no field of an encoded auth", l)
		}
	}
}
