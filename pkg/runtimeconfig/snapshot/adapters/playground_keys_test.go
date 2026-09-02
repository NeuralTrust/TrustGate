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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/adapters"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func publicPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func storeWithKeys(version string, keys ...readmodel.VerificationKey) *configsync.MemoryStore[*readmodel.Snapshot] {
	store := configsync.NewMemoryStore[*readmodel.Snapshot]()
	snap := readmodel.Build(readmodel.Data{Version: version, PlaygroundTokenKeys: keys})
	store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: version, Snapshot: snap})
	return store
}

func TestPlaygroundKeySource_ParsesSnapshotKeys(t *testing.T) {
	t.Parallel()
	store := storeWithKeys("v1", readmodel.VerificationKey{KID: "2026-09", PEM: publicPEM(t)})

	source := adapters.NewPlaygroundKeySource(store)
	keys := source.PlaygroundTokenKeys()
	require.Len(t, keys, 1)
	assert.Contains(t, keys, "2026-09")
}

func TestPlaygroundKeySource_SkipsMalformedEntries(t *testing.T) {
	t.Parallel()
	store := storeWithKeys("v1",
		readmodel.VerificationKey{KID: "good", PEM: publicPEM(t)},
		readmodel.VerificationKey{KID: "bad", PEM: "not-a-key"},
	)

	keys := adapters.NewPlaygroundKeySource(store).PlaygroundTokenKeys()
	require.Len(t, keys, 1)
	assert.Contains(t, keys, "good")
}

func TestPlaygroundKeySource_EmptyStoreReturnsNoKeys(t *testing.T) {
	t.Parallel()
	source := adapters.NewPlaygroundKeySource(configsync.NewMemoryStore[*readmodel.Snapshot]())
	assert.Empty(t, source.PlaygroundTokenKeys())
}

func TestPlaygroundKeySource_FollowsSnapshotRotation(t *testing.T) {
	t.Parallel()
	store := storeWithKeys("v1", readmodel.VerificationKey{KID: "old", PEM: publicPEM(t)})
	source := adapters.NewPlaygroundKeySource(store)
	require.Contains(t, source.PlaygroundTokenKeys(), "old")

	next := readmodel.Build(readmodel.Data{
		Version:             "v2",
		PlaygroundTokenKeys: []readmodel.VerificationKey{{KID: "new", PEM: publicPEM(t)}},
	})
	store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: "v2", Snapshot: next})

	keys := source.PlaygroundTokenKeys()
	assert.Contains(t, keys, "new")
	assert.NotContains(t, keys, "old")
}
