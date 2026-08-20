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
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestCodecRoundTrip(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{Version: "informational-v1"}))
	require.NoError(t, err)

	snap, err := codec.Decode(raw)
	require.NoError(t, err)
	assert.Equal(t, "informational-v1", snap.Data().Version)

	reraw, err := codec.Encode(snap)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(raw, reraw), "decode then re-encode must be byte-identical")
	assert.Equal(t, codec.Version(raw), codec.Version(reraw))
}

func TestEncodeDeterministic(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	raw1, err := codec.Encode(readmodel.Build(readmodel.Data{Version: "v1"}))
	require.NoError(t, err)
	raw2, err := codec.Encode(readmodel.Build(readmodel.Data{Version: "v1"}))
	require.NoError(t, err)

	assert.True(t, bytes.Equal(raw1, raw2), "identical logical config must yield identical bytes")
	assert.Equal(t, codec.Version(raw1), codec.Version(raw2))
}

func TestVersionContentAddressed(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{Version: "v1"}))
	require.NoError(t, err)

	version := codec.Version(raw)
	decoded, err := hex.DecodeString(version)
	require.NoError(t, err)
	assert.Len(t, decoded, 32, "version is a hex SHA-256")

	rawChanged, err := codec.Encode(readmodel.Build(readmodel.Data{Version: "v2"}))
	require.NoError(t, err)
	assert.NotEqual(t, version, codec.Version(rawChanged), "a change yields a new version")
}

func TestEmptySnapshotRoundTrip(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{}))
	require.NoError(t, err)

	snap, err := codec.Decode(raw)
	require.NoError(t, err)
	assert.Empty(t, snap.Data().Version)

	version := codec.Version(raw)
	assert.NotEmpty(t, version)
	raw2, err := codec.Encode(readmodel.Build(readmodel.Data{}))
	require.NoError(t, err)
	assert.Equal(t, version, codec.Version(raw2))
}

func TestDecodeToleratesUnknownFields(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{Version: "v1"}))
	require.NoError(t, err)

	tampered := protowire.AppendTag(raw, 999, protowire.VarintType)
	tampered = protowire.AppendVarint(tampered, 42)

	snap, err := codec.Decode(tampered)
	require.NoError(t, err)
	assert.Equal(t, "v1", snap.Data().Version)
}

func TestEncodeNilSnapshot(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()
	_, err := codec.Encode(nil)
	assert.Error(t, err)
}

func TestDecodeInvalidBytes(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()
	_, err := codec.Decode([]byte{0xff, 0xff, 0xff, 0xff})
	assert.Error(t, err)
}

func TestDecodeIndexesLegacyOIDCAuthAsOAuth2(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	authID := ids.New[ids.AuthKind]()
	gatewayID := ids.New[ids.GatewayKind]()
	entry := fmt.Sprintf(
		`{"id":%q,"gateway_id":%q,"name":"legacy-idp","type":"oidc","enabled":true,`+
			`"config":{"oidc":{"issuer":"https://issuer.example.com","audiences":["gateway"],`+
			`"jwks_url":"https://issuer.example.com/jwks"}}}`,
		authID, gatewayID,
	)
	raw, err := proto.Marshal(&snapshotpb.Snapshot{
		Version: "legacy-v1",
		Auths:   []*snapshotpb.Auth{{Json: []byte(entry)}},
	})
	require.NoError(t, err)

	snap, err := codec.Decode(raw)
	require.NoError(t, err)

	indexed := snap.AuthsEnabledByTypes([]authdomain.Type{authdomain.TypeOAuth2})
	require.Len(t, indexed, 1, "a legacy oidc entry must be indexed as oauth2")
	assert.Equal(t, authID, indexed[0].ID)
	assert.Equal(t, authdomain.TypeOAuth2, indexed[0].Type)
	require.NotNil(t, indexed[0].Config.OAuth2)
	assert.Equal(t, "https://issuer.example.com/jwks", indexed[0].Config.OAuth2.JWKSURL)
	assert.Nil(t, indexed[0].Config.OIDC)

	byGateway := snap.AuthsEnabledByGatewayAndType(gatewayID, authdomain.TypeOAuth2)
	require.Len(t, byGateway, 1)
	assert.Equal(t, authID, byGateway[0].ID)
}

func TestDecodeDefaultsEmptyEntitlementsToFree(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	gw := gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	raw, err := codec.Encode(readmodel.Build(readmodel.Data{Gateways: []gatewaydomain.Gateway{gw}}))
	require.NoError(t, err)

	snap, err := codec.Decode(raw)
	require.NoError(t, err)
	require.Len(t, snap.Data().Gateways, 1)
	assert.Equal(t, gatewaydomain.TierFree, snap.Data().Gateways[0].Entitlements.Tier)
}
