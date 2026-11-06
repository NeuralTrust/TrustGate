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

func TestStoreReadersServeEveryoneFromTheSnapshot(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	store := configsync.NewMemoryStore[*readmodel.Snapshot]()
	store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: "v1", Snapshot: readmodel.Build(readmodel.Data{
		StoreEveryone: []storeaccessdomain.Everyone{{GatewayID: gw, Mode: "curated", Grants: []storeaccessdomain.EveryoneGrant{{CatalogCode: "github"}}}},
	})})

	for name, reader := range map[string]any{"grant reader": adapters.NewStoreGrantReader(store), "policy reader": adapters.NewStorePolicyReader(store)} {
		everyone, ok := reader.(storeaccessdomain.EveryoneReader)
		require.True(t, ok, "the %s must also serve Everyone so the store evaluates it on the data plane", name)
		got, err := everyone.GetEveryone(context.Background(), gw)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "curated", got.Mode)
		got.Grants[0].CatalogCode = "changed"
		again, _ := everyone.GetEveryone(context.Background(), gw)
		assert.Equal(t, "github", again.Grants[0].CatalogCode, "the snapshot's object must not be mutable through the result")
		none, err := everyone.GetEveryone(context.Background(), ids.New[ids.GatewayKind]())
		require.NoError(t, err)
		assert.Nil(t, none)
	}
}

func TestStoreEveryoneBeforeTheFirstSnapshotIsNone(t *testing.T) {
	t.Parallel()
	reader, ok := adapters.NewStoreGrantReader(emptyStore()).(storeaccessdomain.EveryoneReader)
	require.True(t, ok)
	got, err := reader.GetEveryone(context.Background(), ids.New[ids.GatewayKind]())
	require.NoError(t, err)
	assert.Nil(t, got)
}
