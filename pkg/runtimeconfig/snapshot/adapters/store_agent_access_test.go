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

package adapters_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/adapters"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreAgentAccessReaderServesTheSnapshot(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	agent := ids.New[ids.RegistryKind]()
	store := configsync.NewMemoryStore[*readmodel.Snapshot]()
	store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: "v1", Snapshot: readmodel.Build(readmodel.Data{
		StoreAgentAccess: []storeaccessdomain.AgentAccess{
			{GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalGroup, PrincipalID: "eng", Mode: "selected", RegistryIDs: []ids.RegistryID{agent}},
			{GatewayID: ids.New[ids.GatewayKind](), PrincipalType: storeaccessdomain.PrincipalAll, Mode: "all"},
		},
	})})
	reader := adapters.NewStoreAgentAccessReader(store)

	rows, err := reader.ListAgentAccessByGateway(context.Background(), gw)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, []ids.RegistryID{agent}, rows[0].RegistryIDs)
	rows[0].Mode = "none"
	again, _ := reader.ListAgentAccessByGateway(context.Background(), gw)
	assert.Equal(t, "selected", again[0].Mode, "the snapshot's rows must not be mutable through the result")

	none, err := adapters.NewStoreAgentAccessReader(emptyStore()).ListAgentAccessByGateway(context.Background(), gw)
	require.NoError(t, err)
	assert.Empty(t, none)
}
