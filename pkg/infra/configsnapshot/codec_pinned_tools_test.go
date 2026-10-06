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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func mcpRegistry(policy registrydomain.ToolPolicy, decided ...registrydomain.ToolDecision) registrydomain.Registry {
	return registrydomain.Registry{
		ID:          ids.New[ids.RegistryKind](),
		GatewayID:   ids.New[ids.GatewayKind](),
		Name:        "github",
		Type:        registrydomain.TypeMCP,
		ToolPolicy:  policy,
		PinnedTools: decided,
	}
}

func TestCodecRoundTripsPinnedTools(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()
	reg := mcpRegistry(registrydomain.ToolPolicyPinned,
		registrydomain.ToolDecision{Name: "a", Fingerprint: "fa", Status: registrydomain.ToolStatusApproved},
		registrydomain.ToolDecision{Name: "b", Fingerprint: "fb", Status: registrydomain.ToolStatusRejected},
	)

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{Registries: []registrydomain.Registry{reg}}))
	require.NoError(t, err)
	snap, err := codec.Decode(raw)
	require.NoError(t, err)

	got, ok := snap.RegistryByID(reg.ID)
	require.True(t, ok)
	assert.Equal(t, registrydomain.ToolPolicyPinned, got.ToolPolicy)
	assert.Equal(t, reg.PinnedTools, got.PinnedTools)
	assert.True(t, got.IsToolApproved(registrydomain.ToolRef{Name: "a", Fingerprint: "fa"}))
	assert.False(t, got.IsToolApproved(registrydomain.ToolRef{Name: "b", Fingerprint: "fb"}))
}

func TestCodecKeepsAutoRegistryBytesFree(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()
	auto := mcpRegistry(registrydomain.ToolPolicyAuto)

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{Registries: []registrydomain.Registry{auto}}))
	require.NoError(t, err)

	var msg snapshotpb.Snapshot
	require.NoError(t, proto.Unmarshal(raw, &msg))
	require.Len(t, msg.GetRegistries(), 1)
	assert.NotContains(t, string(msg.GetRegistries()[0].GetJson()), "pinned_tools",
		"an auto registry must encode exactly as it did before the field existed")

	empty := auto
	empty.PinnedTools = []registrydomain.ToolDecision{}
	rawEmpty, err := codec.Encode(readmodel.Build(readmodel.Data{Registries: []registrydomain.Registry{empty}}))
	require.NoError(t, err)
	assert.Equal(t, codec.Version(raw), codec.Version(rawEmpty), "nil and empty set are the same bytes")
}

func TestCodecDecodesRegistryWrittenBeforePinning(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()
	id := ids.New[ids.RegistryKind]()
	legacy := `{"id":"` + id.String() + `","name":"old","type":"mcp","enabled":true}`
	raw, err := proto.Marshal(&snapshotpb.Snapshot{Registries: []*snapshotpb.Registry{{Json: []byte(legacy)}}})
	require.NoError(t, err)

	snap, err := codec.Decode(raw)
	require.NoError(t, err)
	got, ok := snap.RegistryByID(id)
	require.True(t, ok)
	assert.Empty(t, got.PinnedTools)
	assert.False(t, got.IsToolApproved(registrydomain.ToolRef{Name: "a", Fingerprint: "fa"}),
		"a missing set means nothing is approved")
}

func TestPinnedRegistryJSONIsReadableByAnOlderDataPlane(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(registrydomain.ToolPolicyPinned,
		registrydomain.ToolDecision{Name: "a", Fingerprint: "fa", Status: registrydomain.ToolStatusApproved})
	blob, err := json.Marshal(reg)
	require.NoError(t, err)

	// A data plane built before the field decodes into a struct without it.
	var older struct {
		ID   ids.RegistryID `json:"id"`
		Name string         `json:"name"`
	}
	require.NoError(t, json.Unmarshal(blob, &older))
	assert.Equal(t, reg.ID, older.ID)
}
