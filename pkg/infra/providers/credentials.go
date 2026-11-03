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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

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
	case registry.AuthTypeGCPServiceAccount:
		if a.GCPServiceAccount != nil && *a.GCPServiceAccount != "" {
			creds.GCP = &GCP{ServiceAccountJSON: *a.GCPServiceAccount}
		}
	case registry.AuthTypeOAuth2:
	case registry.AuthTypePassthrough:
	}
	return creds
}

const (
	bearerPrefix = "Bearer "

	maxServiceAccountKeyBytes = 16 << 10
	serviceAccountKeyType     = "service_account"
)

// ApplyIncomingBearer copies the caller's Authorization token onto credentials
// when the registry auth type is passthrough. The Vertex client already sends
// Credentials.ApiKey as Authorization: Bearer. A caller that sends a
// service-account key instead, as raw or base64 JSON, gets it carried as
// Credentials.GCP so the client mints an access token from it.
func ApplyIncomingBearer(creds *Credentials, auth *registry.TargetAuth, authorization string) {
	if creds == nil || auth == nil || auth.Type != registry.AuthTypePassthrough {
		return
	}
	token := bearerToken(authorization)
	if token == "" {
		return
	}
	if key, ok := serviceAccountKey(token); ok {
		creds.GCP = &GCP{ServiceAccountJSON: key, FromCaller: true}
		return
	}
	creds.ApiKey = token
}

// serviceAccountKey reports whether token is a service-account key file. A dot
// rules out base64 because access tokens (ya29.…) and JWTs always carry one.
func serviceAccountKey(token string) (string, bool) {
	if len(token) > maxServiceAccountKeyBytes {
		return "", false
	}
	raw := []byte(token)
	if token[0] != '{' {
		if strings.Contains(token, ".") {
			return "", false
		}
		decoded, ok := decodeBase64(token)
		if !ok {
			return "", false
		}
		raw = bytes.TrimSpace(decoded)
	}
	var key struct {
		Type string `json:"type"`
	}
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &key) != nil || key.Type != serviceAccountKeyType {
		return "", false
	}
	return string(raw), true
}

func decodeBase64(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

func bearerToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= len(bearerPrefix) && strings.EqualFold(raw[:len(bearerPrefix)], bearerPrefix) {
		return strings.TrimSpace(raw[len(bearerPrefix):])
	}
	return raw
}
