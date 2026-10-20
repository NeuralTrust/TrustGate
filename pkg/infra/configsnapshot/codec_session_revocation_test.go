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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestSessionRevocationRoundTrip(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 19, 12, 0, 0, 123, time.UTC)
	data := readmodel.Data{SessionRevocations: []readmodel.SessionRevocation{{
		GatewayID: "gw-1", Org: "org-1", Subject: "user-1", RevokedAt: at,
	}}}

	raw, err := configsnapshot.NewCodec().Encode(readmodel.Build(data))
	require.NoError(t, err)
	snap, err := configsnapshot.NewCodec().Decode(raw)
	require.NoError(t, err)

	got, ok := snap.SessionRevokedAt("gw-1", "org-1", "user-1")
	require.True(t, ok)
	assert.True(t, got.Equal(at))
	_, ok = snap.SessionRevokedAt("gw-1", "org-1", "other")
	assert.False(t, ok)
}

// A snapshot written before session_revocations exists still decodes. An empty
// list is not a revocation.
func TestOldSnapshotWithoutSessionRevocationsStillDecodes(t *testing.T) {
	t.Parallel()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(&snapshotpb.Snapshot{})
	require.NoError(t, err)

	snap, err := configsnapshot.NewCodec().Decode(raw)
	require.NoError(t, err)
	assert.Empty(t, snap.Data().SessionRevocations)
	_, ok := snap.SessionRevokedAt("gw-1", "org-1", "user-1")
	assert.False(t, ok)
}

// A data plane still on the previous release reads a snapshot that carries
// session_revocations. Proto3 skips unknown fields; this proves it against a
// reader whose schema really lacks field 15. Shipping the field does not block
// a deploy of older data planes.
func TestNewSnapshotIsReadableByAReaderWithoutSessionRevocations(t *testing.T) {
	t.Parallel()
	data := readmodel.Data{SessionRevocations: []readmodel.SessionRevocation{{
		GatewayID: "gw-1", Org: "org-1", Subject: "user-1", RevokedAt: time.Now().UTC(),
	}}}
	raw, err := configsnapshot.NewCodec().Encode(readmodel.Build(data))
	require.NoError(t, err)

	fd := protodesc.ToFileDescriptorProto(snapshotpb.File_snapshot_proto)
	for _, m := range fd.MessageType {
		if m.GetName() != "Snapshot" {
			continue
		}
		kept := make([]*descriptorpb.FieldDescriptorProto, 0, len(m.Field))
		for _, f := range m.Field {
			if f.GetName() != "session_revocations" {
				kept = append(kept, f)
			}
		}
		require.Len(t, kept, len(m.Field)-1, "session_revocations must exist in the current schema")
		m.Field = kept
	}
	files := new(protoregistry.Files)
	oldFile, err := protodesc.NewFile(fd, files)
	require.NoError(t, err)
	oldSnapshot := dynamicpb.NewMessage(oldFile.Messages().ByName(protoreflect.Name("Snapshot")))

	require.NoError(t, proto.Unmarshal(raw, oldSnapshot), "an old reader must not fail on the new field")
}
