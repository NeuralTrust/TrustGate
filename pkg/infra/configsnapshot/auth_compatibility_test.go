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
	"encoding/json"
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func identityProviderFixture() authdomain.Auth {
	return authdomain.Auth{
		ID: ids.New[ids.AuthKind](), GatewayID: ids.New[ids.GatewayKind](),
		Type: authdomain.TypeOAuth2, Enabled: true, KeyHash: "hash-fixture",
		Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
			Issuer: "https://issuer.example", Audiences: []string{"audience"},
			PublicKeys: []string{"inline-key-fixture"}, SubjectClaim: "employee_id",
			Algorithms: []string{"RS256"}, RequiredScopes: []string{"read"},
		}},
	}
}

// legacySnapshotBytes rewrites a canonical auth into the wire shape a
// pre-unification binary wrote — `type: "oidc"` with the payload under
// `config.oidc` — and returns it as an encoded snapshot. Deriving the blob
// from the canonical fixture keeps the two shapes field-for-field identical,
// so a decode difference can only come from canonicalization itself.
func legacySnapshotBytes(t *testing.T, canonical authdomain.Auth) []byte {
	t.Helper()
	blob, err := json.Marshal(canonical)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(blob, &raw))
	raw["type"] = string(authdomain.TypeOIDC)
	config, ok := raw["config"].(map[string]any)
	require.True(t, ok)
	payload, ok := config["oauth2"]
	require.True(t, ok, "canonical fixture must carry an oauth2 payload")
	delete(config, "oauth2")
	config["oidc"] = payload
	legacyBlob, err := json.Marshal(raw)
	require.NoError(t, err)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&snapshotpb.Snapshot{
		Auths: []*snapshotpb.Auth{{Json: legacyBlob, KeyHash: canonical.KeyHash}},
	})
	require.NoError(t, err)
	return encoded
}

// TestSnapshotCanonicalizesLegacyIdentityProvider pins the binary rollback
// floor. A snapshot published by a pre-unification writer must stay readable
// here, and every field has to survive the move onto the oauth2 shape —
// silently dropping `config.oidc` would strip an identity provider of its key
// material at runtime rather than failing loudly.
func TestSnapshotCanonicalizesLegacyIdentityProvider(t *testing.T) {
	t.Parallel()
	canonical := identityProviderFixture()
	codec := configsnapshot.NewCodec()

	decoded, err := codec.Decode(legacySnapshotBytes(t, canonical))
	require.NoError(t, err)
	require.Equal(t, []authdomain.Auth{canonical}, decoded.Data().Auths)
}

// TestSnapshotCanonicalizationIsIdempotent proves canonicalization settles:
// re-encoding a decoded legacy snapshot yields bytes identical to encoding the
// canonical fixture directly, so a mixed-version fleet cannot flip an auth
// between two representations on every republish.
func TestSnapshotCanonicalizationIsIdempotent(t *testing.T) {
	t.Parallel()
	canonical := identityProviderFixture()
	codec := configsnapshot.NewCodec()

	decoded, err := codec.Decode(legacySnapshotBytes(t, canonical))
	require.NoError(t, err)
	reencoded, err := codec.Encode(decoded)
	require.NoError(t, err)

	native, err := codec.Encode(readmodel.Build(readmodel.Data{Auths: []authdomain.Auth{canonical}}))
	require.NoError(t, err)
	require.Equal(t, native, reencoded)

	stable, err := codec.Decode(reencoded)
	require.NoError(t, err)
	require.Equal(t, decoded.Data().Auths, stable.Data().Auths)
}

// TestSnapshotPreservesNativeIdentityProvider keeps the unchanged-shape
// guarantee for auths already written as oauth2, including inline keys.
func TestSnapshotPreservesNativeIdentityProvider(t *testing.T) {
	t.Parallel()
	canonical := identityProviderFixture()
	codec := configsnapshot.NewCodec()

	encoded, err := codec.Encode(readmodel.Build(readmodel.Data{Auths: []authdomain.Auth{canonical}}))
	require.NoError(t, err)
	decoded, err := codec.Decode(encoded)
	require.NoError(t, err)
	require.Equal(t, []authdomain.Auth{canonical}, decoded.Data().Auths)
	reencoded, err := codec.Encode(decoded)
	require.NoError(t, err)
	require.Equal(t, encoded, reencoded)
}
