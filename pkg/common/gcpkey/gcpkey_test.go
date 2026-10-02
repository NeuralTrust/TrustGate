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

package gcpkey

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func keyJSON(t *testing.T, fields map[string]string) string {
	t.Helper()
	base := map[string]string{
		"type":         "service_account",
		"project_id":   "careplus-poc",
		"private_key":  "placeholder",
		"client_email": "sa@careplus-poc.iam.gserviceaccount.com",
	}
	for k, v := range fields {
		if v == "" {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	raw, err := json.Marshal(base)
	require.NoError(t, err)
	return string(raw)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "google token_uri", raw: keyJSON(t, map[string]string{"token_uri": "https://oauth2.googleapis.com/token"})},
		{name: "legacy token_uri", raw: keyJSON(t, map[string]string{"token_uri": "https://accounts.google.com/o/oauth2/token"})},
		{name: "v4 token_uri", raw: keyJSON(t, map[string]string{"token_uri": "https://www.googleapis.com/oauth2/v4/token"})},
		{name: "absent token_uri", raw: keyJSON(t, nil)},
		{name: "default universe", raw: keyJSON(t, map[string]string{"universe_domain": "googleapis.com"})},
		{name: "cluster service token_uri", raw: keyJSON(t, map[string]string{"token_uri": "http://trustgate.svc.cluster.local:8080/x"}), wantErr: "token_uri"},
		{name: "metadata server token_uri", raw: keyJSON(t, map[string]string{"token_uri": "http://169.254.169.254/computeMetadata/v1/"}), wantErr: "token_uri"},
		{name: "lookalike host token_uri", raw: keyJSON(t, map[string]string{"token_uri": "https://oauth2.googleapis.com.evil.example/token"}), wantErr: "token_uri"},
		{name: "userinfo token_uri", raw: keyJSON(t, map[string]string{"token_uri": "https://oauth2.googleapis.com@evil.example/token"}), wantErr: "token_uri"},
		{name: "http token_uri", raw: keyJSON(t, map[string]string{"token_uri": "http://oauth2.googleapis.com/token"}), wantErr: "token_uri"},
		{name: "trailing slash token_uri", raw: keyJSON(t, map[string]string{"token_uri": "https://oauth2.googleapis.com/token/"}), wantErr: "token_uri"},
		{name: "uppercase host token_uri", raw: keyJSON(t, map[string]string{"token_uri": "https://OAUTH2.googleapis.com/token"}), wantErr: "token_uri"},
		{
			name:    "duplicate token_uri hostile last",
			raw:     `{"type":"service_account","token_uri":"https://oauth2.googleapis.com/token","token_uri":"http://evil.example/x"}`,
			wantErr: "token_uri",
		},
		{
			name:    "case-variant key hostile",
			raw:     `{"type":"service_account","Token_URI":"http://evil.example/x"}`,
			wantErr: "token_uri",
		},
		{name: "custom universe", raw: keyJSON(t, map[string]string{"universe_domain": "evil.example"}), wantErr: "universe_domain"},
		{name: "external_account", raw: keyJSON(t, map[string]string{"type": "external_account"}), wantErr: "type"},
		{name: "impersonated_service_account", raw: keyJSON(t, map[string]string{"type": "impersonated_service_account"}), wantErr: "type"},
		{name: "authorized_user", raw: keyJSON(t, map[string]string{"type": "authorized_user"}), wantErr: "type"},
		{name: "missing type", raw: keyJSON(t, map[string]string{"type": ""}), wantErr: "type"},
		{name: "not json", raw: "{not-json", wantErr: "JSON object"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.raw)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.NotContains(t, err.Error(), "placeholder", "the error must never echo the credential")
			assert.NotContains(t, err.Error(), "evil.example")
			assert.NotContains(t, err.Error(), "169.254")
		})
	}
}
