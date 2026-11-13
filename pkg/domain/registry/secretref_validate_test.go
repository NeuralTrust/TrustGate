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

import "testing"

// TestValidateAcceptsReferencesAtEveryCredential runs every auth type with
// a secret reference in place of each credential: literal-only checks such
// as parsing a GCP key must not refuse it.
func TestValidateAcceptsReferencesAtEveryCredential(t *testing.T) {
	t.Parallel()
	ref := "secret://corp-vault/ai/key"
	sa := ref
	auths := []*TargetAuth{
		{Type: AuthTypeAPIKey, APIKey: &APIKeyAuth{APIKey: ref}},
		{Type: AuthTypeAPIKey, APIKey: &APIKeyAuth{HeaderName: "X-K", HeaderValue: ref}},
		{Type: AuthTypeAWS, AWS: &AWSAuth{Region: "eu-west-1", AccessKeyID: ref, SecretAccessKey: ref, SessionToken: ref}},
		{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://az", APIKey: ref}},
		{Type: AuthTypeOAuth2, OAuth: &TargetOAuthConfig{TokenURL: "https://t", GrantType: "client_credentials", ClientID: "c", ClientSecret: ref}},
		{Type: AuthTypeGCPServiceAccount, GCPServiceAccount: &sa},
	}
	for _, a := range auths {
		if err := a.Validate(); err != nil {
			t.Errorf("%s with a reference: %v", a.Type, err)
		}
	}
	bad := "not json"
	if err := (&TargetAuth{Type: AuthTypeGCPServiceAccount, GCPServiceAccount: &bad}).Validate(); err == nil {
		t.Error("a literal GCP key must still be checked")
	}
}
