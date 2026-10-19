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

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestUsageEnforcementRoundTrip(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()
	data := readmodel.Data{Gateways: []gatewaydomain.Gateway{stampedGateway("tenant-1")}, UsageEnforcement: true}

	raw, err := codec.Encode(readmodel.Build(data))
	require.NoError(t, err)
	snap, err := codec.Decode(raw)
	require.NoError(t, err)
	assert.True(t, snap.UsageEnforcement())
}

// With the feature off the encoded bytes, and so the snapshot version every
// data plane compares, must stay what a control plane without the feature
// produces, or the deploy alone would make every data plane re-fetch: the
// field must not appear on the wire at all.
func TestUsageEnforcementOffKeepsBytesUnchanged(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()
	gw := stampedGateway("tenant-1")
	off, err := codec.Encode(readmodel.Build(readmodel.Data{Gateways: []gatewaydomain.Gateway{gw}}))
	require.NoError(t, err)
	on, err := codec.Encode(readmodel.Build(readmodel.Data{Gateways: []gatewaydomain.Gateway{gw}, UsageEnforcement: true}))
	require.NoError(t, err)

	assert.False(t, hasTopLevelField(t, off, usageEnforcementField))
	assert.True(t, hasTopLevelField(t, on, usageEnforcementField))
	assert.NotEqual(t, codec.Version(off), codec.Version(on))
}

const usageEnforcementField = 16

func hasTopLevelField(t *testing.T, raw []byte, field protowire.Number) bool {
	t.Helper()
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		require.GreaterOrEqual(t, n, 0, "malformed tag")
		raw = raw[n:]
		if num == field {
			return true
		}
		n = protowire.ConsumeFieldValue(num, typ, raw)
		require.GreaterOrEqual(t, n, 0, "malformed field")
		raw = raw[n:]
	}
	return false
}
