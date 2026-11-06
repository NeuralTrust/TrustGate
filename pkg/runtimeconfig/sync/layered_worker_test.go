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

package configsync

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type verifyingFetcher struct {
	fakeFetcher
	prefix string
}

func (f *verifyingFetcher) Verifies(version string) bool {
	return strings.HasPrefix(version, f.prefix)
}

func TestWorker_ConvergeTrustsAVersionTheFetcherVerified(t *testing.T) {
	t.Parallel()

	fetcher := &verifyingFetcher{prefix: "m1:", fakeFetcher: fakeFetcher{results: []fetchResult{{raw: []byte("assembled"), version: "m1:manifest"}}}}
	store := NewMemoryStore[string]()
	transport := &fakeTransport{}
	worker := NewWorker[string](fetcher, store, transport, nil, stringCodec{}, nil, WorkerConfig{})

	require.NoError(t, worker.Converge(context.Background()))
	snap, ok := snapshotOf(t, store)
	require.True(t, ok)
	assert.Equal(t, "assembled", snap)
	assert.Equal(t, "m1:manifest", store.Version())
	assert.Equal(t, []string{"m1:manifest"}, transport.ackedVersions())
}

func TestWorker_ConvergeStillChecksVersionsTheFetcherDoesNotVerify(t *testing.T) {
	t.Parallel()

	fetcher := &verifyingFetcher{prefix: "m1:", fakeFetcher: fakeFetcher{results: []fetchResult{{raw: []byte("tampered"), version: "not-the-hash"}}}}
	worker := NewWorker[string](fetcher, NewMemoryStore[string](), &fakeTransport{}, nil, stringCodec{}, nil, WorkerConfig{})

	require.ErrorIs(t, worker.Converge(context.Background()), ErrIntegrity)
}

func TestWorker_LayeredSnapshotRestoredFromLKGConvergesToTheNextManifest(t *testing.T) {
	t.Parallel()

	crypto, err := NewAESGCMCrypto(newTestKey())
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "lkg.enc")
	lkg := NewLKGStore[string](crypto, stringCodec{}, path)

	first := &verifyingFetcher{prefix: "m1:", fakeFetcher: fakeFetcher{results: []fetchResult{{raw: []byte("layered-one"), version: "m1:one"}}}}
	require.NoError(t, NewWorker[string](first, NewMemoryStore[string](), &fakeTransport{}, lkg, stringCodec{}, nil, WorkerConfig{}).Converge(context.Background()))

	second := &verifyingFetcher{prefix: "m1:", fakeFetcher: fakeFetcher{results: []fetchResult{{raw: []byte("layered-two"), version: "m1:two"}}}}
	store := NewMemoryStore[string]()
	restarted := NewWorker[string](second, store, &fakeTransport{}, lkg, stringCodec{}, nil, WorkerConfig{})
	restarted.restoreLKG()
	snap, ok := snapshotOf(t, store)
	require.True(t, ok)
	assert.Equal(t, "layered-one", snap, "the restarted data plane serves the persisted layered snapshot")

	require.NoError(t, restarted.Converge(context.Background()))
	snap, _ = snapshotOf(t, store)
	assert.Equal(t, "layered-two", snap)
	assert.Equal(t, "m1:two", store.Version())
	assert.Equal(t, []string{stringCodec{}.Version([]byte("layered-one"))}, second.etags,
		"after a restart the data plane asks with the hash of the restored bytes, which never matches a manifest, so it pulls the manifest again")
}
