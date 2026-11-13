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
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// TestCredentialsNeverCarryAReference runs a reference-shaped value through
// every credential field: whatever reached here unresolved must not be sent.
func TestCredentialsNeverCarryAReference(t *testing.T) {
	t.Parallel()
	ref := "secret://vault/ai/openai#api_key"
	sa := ref
	auths := []*registry.TargetAuth{
		{Type: registry.AuthTypeAPIKey, APIKey: &registry.APIKeyAuth{APIKey: ref, HeaderName: "X-K", HeaderValue: ref}},
		{Type: registry.AuthTypeAWS, AWS: &registry.AWSAuth{AccessKeyID: ref, SecretAccessKey: ref, SessionToken: ref, Region: "eu-west-1"}},
		{Type: registry.AuthTypeAzure, Azure: &registry.AzureAuth{APIKey: ref, ClientSecret: ref, Endpoint: "https://az"}},
		{Type: registry.AuthTypeGCPServiceAccount, GCPServiceAccount: &sa},
	}
	for _, a := range auths {
		creds := providers.CredentialsFromTargetAuth(a)
		dump := creds.ApiKey
		for k, v := range creds.Headers {
			dump += k + v
		}
		if creds.AwsBedrock != nil {
			dump += creds.AwsBedrock.AccessKey + creds.AwsBedrock.SecretKey + creds.AwsBedrock.SessionToken
		}
		if creds.Azure != nil {
			dump += creds.Azure.ClientSecret
		}
		if creds.GCP != nil {
			dump += creds.GCP.ServiceAccountJSON
		}
		if strings.Contains(dump, "secret://") {
			t.Fatalf("%s credentials carry the reference: %+v", a.Type, creds)
		}
	}
	if got := providers.CredentialsFromTargetAuth(registry.NewAPIKeyAuth("sk-live")).ApiKey; got != "sk-live" {
		t.Fatalf("literal key = %q", got)
	}
}
