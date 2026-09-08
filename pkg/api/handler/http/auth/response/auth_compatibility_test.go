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

const identityProviderPayload = `{
    "issuer":"urn:example:idp","audiences":["gateway"],"public_keys":["public-key"],
    "required_scopes":["read"],"allowed_algorithms":["RS256"],"subject_claim":"employee_id"
   }`

// TestAuthRequestAcceptsLegacyIdentityProviderWire pins the ingest half of the
// compatibility contract. Canonicalization means a legacy request no longer
// round-trips byte-for-byte, so what is guaranteed instead is that it is still
// accepted and converges on exactly the auth the canonical form produces. A
// client pinned to the deprecated alias keeps working and loses no field.
func TestAuthRequestAcceptsLegacyIdentityProviderWire(t *testing.T) {
	t.Parallel()
	legacyInput := []byte(`{"name":"original","type":"oidc","config":{"oidc":` + identityProviderPayload + `}}`)
	canonicalInput := []byte(`{"name":"original","type":"oauth2","config":{"oauth2":` + identityProviderPayload + `}}`)

	var legacy, canonical request.CreateAuthRequest
	require.NoError(t, json.Unmarshal(legacyInput, &legacy))
	require.NoError(t, json.Unmarshal(canonicalInput, &canonical))

	require.Equal(t, canonical.Config.ToDomain(), legacy.Config.ToDomain())
	require.NotNil(t, legacy.Config.ToDomain().OAuth2)

	gatewayID := ids.New[ids.GatewayKind]()
	fromLegacy, err := domain.NewAuth(gatewayID, legacy.Name, domain.NormalizeType(domain.Type(legacy.Type)), true, legacy.Config.ToDomain())
	require.NoError(t, err)
	fromCanonical, err := domain.NewAuth(gatewayID, canonical.Name, domain.NormalizeType(domain.Type(canonical.Type)), true, canonical.Config.ToDomain())
	require.NoError(t, err)

	require.Equal(t, domain.TypeOAuth2, fromLegacy.Type)
	require.Equal(t, fromCanonical.Config, fromLegacy.Config)
}

// TestAuthResponseSurvivesRenameOnlyEdit covers the read-modify-write path a
// console performs on an auth it did not create: reading the response and
// posting it back with a new name must not drop the identity-provider config.
func TestAuthResponseSurvivesRenameOnlyEdit(t *testing.T) {
	t.Parallel()
	input := []byte(`{"name":"original","type":"oauth2","config":{"oauth2":` + identityProviderPayload + `}}`)
	var create request.CreateAuthRequest
	require.NoError(t, json.Unmarshal(input, &create))
	original, err := domain.NewAuth(ids.New[ids.GatewayKind](), create.Name, domain.TypeOAuth2, true, create.Config.ToDomain())
	require.NoError(t, err)

	wire, err := json.Marshal(response.FromAuth(original))
	require.NoError(t, err)
	var edit request.CreateAuthRequest
	require.NoError(t, json.Unmarshal(wire, &edit))
	edit.Name = "renamed"

	require.Equal(t, string(domain.TypeOAuth2), edit.Type)
	require.Equal(t, original.Config, edit.Config.ToDomain())
	require.NotNil(t, edit.Config.OAuth2)
	require.Nil(t, edit.Config.OIDC)
}
