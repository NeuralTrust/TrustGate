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

package providers

import (
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// CredentialsFromTargetAuth maps a registry target's auth configuration onto
// the provider credentials DTO consumed by the provider clients.
func CredentialsFromTargetAuth(a *registry.TargetAuth) Credentials {
	creds := Credentials{}
	if a == nil {
		return creds
	}
	switch a.Type {
	case registry.AuthTypeAPIKey:
		if a.APIKey != nil {
			creds.ApiKey = a.APIKey.APIKey
		}
	case registry.AuthTypeAWS:
		if a.AWS != nil {
			creds.AwsBedrock = &AwsBedrock{
				Region:       a.AWS.Region,
				AccessKey:    a.AWS.AccessKeyID,
				SecretKey:    a.AWS.SecretAccessKey,
				SessionToken: a.AWS.SessionToken,
				UseRole:      a.AWS.UseRole,
				RoleARN:      a.AWS.Role,
			}
		}
	case registry.AuthTypeAzure:
		if a.Azure != nil {
			mode, _ := a.Azure.CredentialMode()
			creds.ApiKey = a.Azure.APIKey
			creds.Azure = &Azure{
				Endpoint:     a.Azure.Endpoint,
				ApiVersion:   a.Azure.Version,
				AuthMode:     AzureAuthMode(mode),
				UseIdentity:  a.Azure.UseManagedIdentity,
				TenantID:     a.Azure.TenantID,
				ClientID:     a.Azure.ClientID,
				ClientSecret: a.Azure.ClientSecret,
			}
		}
	case registry.AuthTypeOAuth2, registry.AuthTypeGCPServiceAccount:
	}
	return creds
}
