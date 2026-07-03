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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLKG(t *testing.T) (*LKGStore[string], string) {
	t.Helper()
	crypto, err := NewAESGCMCrypto(newTestKey())
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "lkg.enc")
	return NewLKGStore[string](crypto, stringCodec{}, path), path
}

func TestLKGStore_PersistLoadRoundtrip(t *testing.T) {
	t.Parallel()

	store, _ := newTestLKG(t)
	codec := stringCodec{}
	raw, err := codec.Encode("snapshot-payload")
	require.NoError(t, err)

	original := &Versioned[string]{Version: codec.Version(raw), Snapshot: "snapshot-payload", Raw: raw}
	require.NoError(t, store.Persist(original))

	loaded, err := store.Load()
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, original.Version, loaded.Version)
	assert.Equal(t, original.Snapshot, loaded.Snapshot)
	assert.Equal(t, original.Raw, loaded.Raw)
}

func TestLKGStore_LoadMissingFile(t *testing.T) {
	t.Parallel()

	store, _ := newTestLKG(t)
	loaded, err := store.Load()
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestLKGStore_CorruptBlob(t *testing.T) {
	t.Parallel()

	store, path := newTestLKG(t)
	require.NoError(t, os.WriteFile(path, []byte("not-a-valid-ciphertext"), 0o600))

	_, err := store.Load()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLKGCorrupt))
}

func TestLKGStore_WrongKeyIsCorrupt(t *testing.T) {
	t.Parallel()

	store, path := newTestLKG(t)
	codec := stringCodec{}
	raw, err := codec.Encode("payload")
	require.NoError(t, err)
	require.NoError(t, store.Persist(&Versioned[string]{Version: codec.Version(raw), Snapshot: "payload", Raw: raw}))

	otherKey := newTestKey()
	otherKey[0] ^= 0xFF
	otherCrypto, err := NewAESGCMCrypto(otherKey)
	require.NoError(t, err)
	otherStore := NewLKGStore[string](otherCrypto, codec, path)

	_, err = otherStore.Load()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLKGCorrupt))
}

func TestLKGStore_PersistNilNoop(t *testing.T) {
	t.Parallel()

	store, path := newTestLKG(t)
	require.NoError(t, store.Persist(nil))
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestLKGStore_Age(t *testing.T) {
	t.Parallel()

	store, _ := newTestLKG(t)

	if _, ok := store.Age(); ok {
		t.Fatalf("Age must report false before any blob is written")
	}

	codec := stringCodec{}
	raw, err := codec.Encode("payload")
	require.NoError(t, err)
	require.NoError(t, store.Persist(&Versioned[string]{Version: codec.Version(raw), Snapshot: "payload", Raw: raw}))

	age, ok := store.Age()
	require.True(t, ok)
	assert.GreaterOrEqual(t, age, time.Duration(0))
	assert.Less(t, age, time.Minute)
}

func TestLKGStore_PersistOverwrites(t *testing.T) {
	t.Parallel()

	store, _ := newTestLKG(t)
	codec := stringCodec{}

	rawA, err := codec.Encode("first")
	require.NoError(t, err)
	require.NoError(t, store.Persist(&Versioned[string]{Version: codec.Version(rawA), Snapshot: "first", Raw: rawA}))

	rawB, err := codec.Encode("second")
	require.NoError(t, err)
	require.NoError(t, store.Persist(&Versioned[string]{Version: codec.Version(rawB), Snapshot: "second", Raw: rawB}))

	loaded, err := store.Load()
	require.NoError(t, err)
	assert.Equal(t, "second", loaded.Snapshot)
}
