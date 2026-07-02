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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/configsnapshot/readmodel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
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
