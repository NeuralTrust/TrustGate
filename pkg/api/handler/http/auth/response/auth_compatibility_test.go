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

package response_test

import (
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth/response"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

func TestAuthResponsePreservesIdentityProviderWireContract(t *testing.T) {
	t.Parallel()
	for _, authType := range []domain.Type{domain.TypeOIDC, domain.TypeOAuth2} {
		t.Run(string(authType), func(t *testing.T) {
			t.Parallel()
			input := []byte(`{"name":"original","type":"` + string(authType) + `","config":{"` + string(authType) + `":{
    "issuer":"urn:example:idp","audiences":["gateway"],"public_keys":["public-key"],
    "required_scopes":["read"],"allowed_algorithms":["RS256"],"subject_claim":"employee_id"
   }}}`)
			var create request.CreateAuthRequest
			require.NoError(t, json.Unmarshal(input, &create))
			original, err := domain.NewAuth(ids.New[ids.GatewayKind](), create.Name, authType, true, create.Config.ToDomain())
			require.NoError(t, err)
			wire, err := json.Marshal(response.FromAuth(original))
			require.NoError(t, err)
			var edit request.CreateAuthRequest
			require.NoError(t, json.Unmarshal(wire, &edit))
			edit.Name = "renamed"
			require.Equal(t, string(authType), edit.Type)
			require.Equal(t, original.Config, edit.Config.ToDomain())
			if authType == domain.TypeOIDC {
				require.Nil(t, edit.Config.OAuth2)
				require.NotNil(t, edit.Config.OIDC)
			} else {
				require.Nil(t, edit.Config.OIDC)
				require.NotNil(t, edit.Config.OAuth2)
			}
		})
	}
}
