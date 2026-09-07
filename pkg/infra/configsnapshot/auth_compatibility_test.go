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

package configsnapshot_test

import (
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/require"
)

func TestSnapshotPreservesIdentityProviderContracts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		kind   authdomain.Type
		config authdomain.Config
	}{
		{
			name: "legacy oidc",
			kind: authdomain.TypeOIDC,
			config: authdomain.Config{OIDC: &authdomain.OIDCConfig{
				Issuer: "https://issuer.example", Audiences: []string{"audience"},
				PublicKeys: []string{"inline-key-fixture"}, SubjectClaim: "employee_id",
				AllowedAlgorithms: []string{"RS256"}, RequiredScopes: []string{"read"},
			}},
		},
		{
			name: "oauth2 inline keys",
			kind: authdomain.TypeOAuth2,
			config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
				Issuer: "https://issuer.example", Audiences: []string{"audience"},
				PublicKeys: []string{"inline-key-fixture"}, SubjectClaim: "employee_id",
				Algorithms: []string{"RS256"}, RequiredScopes: []string{"read"},
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			original := authdomain.Auth{
				ID: ids.New[ids.AuthKind](), GatewayID: ids.New[ids.GatewayKind](),
				Type: tc.kind, Config: tc.config, Enabled: true, KeyHash: "hash-fixture",
			}
			codec := configsnapshot.NewCodec()
			encoded, err := codec.Encode(readmodel.Build(readmodel.Data{Auths: []authdomain.Auth{original}}))
			require.NoError(t, err)
			decoded, err := codec.Decode(encoded)
			require.NoError(t, err)
			require.Equal(t, []authdomain.Auth{original}, decoded.Data().Auths)
			reencoded, err := codec.Encode(decoded)
			require.NoError(t, err)
			require.Equal(t, encoded, reencoded)
		})
	}
}
