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

package request

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/require"
)

const sampleServiceAccount = `{
  "type": "service_account",
  "project_id": "cpai-sandbox",
  "private_key": "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n",
  "client_email": "vertex@cpai-sandbox.iam.gserviceaccount.com"
}`

func TestGCPServiceAccountJSON_UnmarshalJSON_Object(t *testing.T) {
	t.Parallel()

	var auth TargetAuthRequest
	err := json.Unmarshal([]byte(`{
		"type":"gcp_service_account",
		"gcp_service_account":{
			"type":"service_account",
			"project_id":"cpai-sandbox",
			"client_email":"vertex@cpai-sandbox.iam.gserviceaccount.com",
			"private_key":"k"
		}
	}`), &auth)
	require.NoError(t, err)
	require.NotNil(t, auth.GCPServiceAccount)
	require.False(t, strings.Contains(string(*auth.GCPServiceAccount), "\n"))
	require.Equal(t, "cpai-sandbox", projectIDFromServiceAccount(string(*auth.GCPServiceAccount)))

	domainAuth := auth.ToDomain()
	require.NotNil(t, domainAuth.GCPServiceAccount)
	require.Equal(t, string(*auth.GCPServiceAccount), *domainAuth.GCPServiceAccount)
}

func TestGCPServiceAccountJSON_UnmarshalJSON_PrettyString(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(map[string]any{
		"type":                "gcp_service_account",
		"gcp_service_account": sampleServiceAccount,
	})
	require.NoError(t, err)

	var auth TargetAuthRequest
	require.NoError(t, json.Unmarshal(payload, &auth))
	require.NotNil(t, auth.GCPServiceAccount)
	require.False(t, strings.Contains(string(*auth.GCPServiceAccount), "\n"))
	require.JSONEq(t, `{"type":"service_account","project_id":"cpai-sandbox","private_key":"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n","client_email":"vertex@cpai-sandbox.iam.gserviceaccount.com"}`, string(*auth.GCPServiceAccount))
}

func TestCreateRegistryRequest_Normalize_InfersVertexProject(t *testing.T) {
	t.Parallel()

	sa := GCPServiceAccountJSON(compactServiceAccountJSON(sampleServiceAccount))
	req := CreateRegistryRequest{
		Name:     "vertex-reg",
		Provider: providers.ProviderVertex,
		ProviderOptions: map[string]any{
			"location": "europe-west1",
		},
		Auth: &TargetAuthRequest{
			Type:              "gcp_service_account",
			GCPServiceAccount: &sa,
		},
	}
	req.Normalize()
	require.Equal(t, "cpai-sandbox", req.ProviderOptions["project"])
	require.Equal(t, "europe-west1", req.ProviderOptions["location"])
}

func TestTestConnectionRequest_Normalize_InfersVertexProject(t *testing.T) {
	t.Parallel()

	sa := GCPServiceAccountJSON(compactServiceAccountJSON(sampleServiceAccount))
	req := TestConnectionRequest{
		Provider: providers.ProviderVertex,
		ProviderOptions: map[string]any{
			"location": "us-central1",
		},
		Auth: &TargetAuthRequest{
			Type:              "gcp_service_account",
			GCPServiceAccount: &sa,
		},
	}
	req.Normalize()
	require.Equal(t, "cpai-sandbox", req.ProviderOptions["project"])
}

func TestUpdateRegistryRequest_Normalize_InfersVertexProject(t *testing.T) {
	t.Parallel()

	sa := GCPServiceAccountJSON(compactServiceAccountJSON(sampleServiceAccount))
	provider := providers.ProviderVertex
	options := map[string]any{"location": "europe-west1"}
	req := UpdateRegistryRequest{
		Provider:        &provider,
		ProviderOptions: &options,
		Auth: &TargetAuthRequest{
			Type:              "gcp_service_account",
			GCPServiceAccount: &sa,
		},
	}
	req.Normalize()
	require.NotNil(t, req.ProviderOptions)
	require.Equal(t, "cpai-sandbox", (*req.ProviderOptions)["project"])
}

func TestCreateRegistryRequest_Normalize_KeepsExplicitProject(t *testing.T) {
	t.Parallel()

	sa := GCPServiceAccountJSON(compactServiceAccountJSON(sampleServiceAccount))
	req := CreateRegistryRequest{
		Name:     "vertex-reg",
		Provider: providers.ProviderVertex,
		ProviderOptions: map[string]any{
			"project":  "override-project",
			"location": "europe-west1",
		},
		Auth: &TargetAuthRequest{
			Type:              "gcp_service_account",
			GCPServiceAccount: &sa,
		},
	}
	req.Normalize()
	require.Equal(t, "override-project", req.ProviderOptions["project"])
}
