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

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
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

func stampedGateway(tenant string) gatewaydomain.Gateway {
	burst, quota, inst := 300, 100000, 5
	return gatewaydomain.Gateway{
		ID:       ids.New[ids.GatewayKind](),
		Slug:     "acme",
		Metadata: map[string]string{gatewaydomain.MetadataTenantIDKey: tenant},
		Entitlements: gatewaydomain.Entitlements{
			Tier: "standard", BurstPerMin: &burst, QuotaPerMonth: &quota, MaxInstances: &inst,
		},
	}
}

func TestTenantCapsRoundTrip(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()
	data := readmodel.Data{
		Gateways: []gatewaydomain.Gateway{stampedGateway("tenant-1")},
		TenantCaps: []ratelimitdomain.TenantCaps{
			{TenantID: "tenant-1", Tier: "standard", BurstPerMin: 300, QuotaPerMonth: 100000, MaxInstances: 5},
			{TenantID: "tenant-2", Tier: "enterprise", BurstPerMin: 1000, QuotaPerMonth: 0, MaxInstances: 5},
		},
	}

	raw, err := codec.Encode(readmodel.Build(data))
	require.NoError(t, err)
	snap, err := codec.Decode(raw)
	require.NoError(t, err)

	c1, ok := snap.TenantCapsByTenantID("tenant-1")
	require.True(t, ok)
	assert.Equal(t, data.TenantCaps[0], *c1)

	c2, ok := snap.TenantCapsByTenantID("tenant-2")
	require.True(t, ok)
	assert.Equal(t, 0, c2.QuotaPerMonth, "0 stays the unlimited sentinel")

	_, ok = snap.TenantCapsByTenantID("tenant-unknown")
	assert.False(t, ok)
}

// A snapshot written by the previous release has no tenant_caps. The data plane
// must still decode it and keep the per-gateway stamp it carries, because that is
// what it meters with until the control plane publishes the new shape.
func TestOldSnapshotWithoutTenantCapsStillDecodesAndKeepsGatewayStamp(t *testing.T) {
	t.Parallel()
	gw := stampedGateway("tenant-1")
	blob := mustMarshalGateway(t, gw)
	old := &snapshotpb.Snapshot{Gateways: []*snapshotpb.Gateway{{Json: blob}}}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(old)
	require.NoError(t, err)

	snap, err := configsnapshot.NewCodec().Decode(raw)
	require.NoError(t, err)

	_, ok := snap.TenantCapsByTenantID("tenant-1")
	assert.False(t, ok, "an old snapshot carries no tenant caps")
	g, ok := snap.GatewayByID(gw.ID)
	require.True(t, ok)
	limits, stamped := g.Entitlements.ResolveLimits()
	require.True(t, stamped)
	assert.Equal(t, ratelimitdomain.Limits{BurstPerMin: 300, QuotaPerMonth: 100000, MaxInstances: 5}, limits)
}

// The reverse direction: a data plane still on the previous release reads a
// snapshot that carries tenant_caps. Proto3 skips unknown fields, but that is the
// property this rollout relies on, so it is proved against a reader whose schema
// really lacks field 14 instead of being assumed.
func TestNewSnapshotIsReadableByAReaderWithoutTenantCaps(t *testing.T) {
	t.Parallel()
	data := readmodel.Data{
		Gateways:   []gatewaydomain.Gateway{stampedGateway("tenant-1")},
		TenantCaps: []ratelimitdomain.TenantCaps{{TenantID: "tenant-1", Tier: "standard", BurstPerMin: 300, QuotaPerMonth: 1, MaxInstances: 5}},
	}
	raw, err := configsnapshot.NewCodec().Encode(readmodel.Build(data))
	require.NoError(t, err)

	fd := protodesc.ToFileDescriptorProto(snapshotpb.File_snapshot_proto)
	for _, m := range fd.MessageType {
		if m.GetName() != "Snapshot" {
			continue
		}
		kept := make([]*descriptorpb.FieldDescriptorProto, 0, len(m.Field))
		for _, f := range m.Field {
			if f.GetName() != "tenant_caps" {
				kept = append(kept, f)
			}
		}
		require.Len(t, kept, len(m.Field)-1, "tenant_caps must exist in the current schema")
		m.Field = kept
	}
	oldFile, err := protodesc.NewFile(fd, protoregistry.GlobalFiles)
	require.NoError(t, err)
	oldSnapshot := dynamicpb.NewMessage(oldFile.Messages().ByName(protoreflect.Name("Snapshot")))

	require.NoError(t, proto.Unmarshal(raw, oldSnapshot), "an old reader must not fail on the new field")
	gateways := oldSnapshot.Get(oldSnapshot.Descriptor().Fields().ByName("gateways")).List()
	assert.Equal(t, len(data.Gateways), gateways.Len())
}

func mustMarshalGateway(t *testing.T, g gatewaydomain.Gateway) []byte {
	t.Helper()
	blob, err := json.Marshal(&g)
	require.NoError(t, err)
	return blob
}
