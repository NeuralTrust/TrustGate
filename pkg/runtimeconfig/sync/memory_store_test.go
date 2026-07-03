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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_LoadSwapVersion(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore[string]()

	got, ok := store.Load()
	assert.False(t, ok)
	assert.Nil(t, got)
	assert.Equal(t, "", store.Version())

	first := &Versioned[string]{Version: "v1", Snapshot: "one", Raw: []byte("one")}
	store.Swap(first)

	got, ok = store.Load()
	require.True(t, ok)
	assert.Equal(t, first, got)
	assert.Equal(t, "v1", store.Version())

	second := &Versioned[string]{Version: "v2", Snapshot: "two", Raw: []byte("two")}
	store.Swap(second)
	assert.Equal(t, "v2", store.Version())
}

func TestMemoryStore_ConcurrentSwapLoad(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore[string]()
	store.Swap(&Versioned[string]{Version: "v0", Snapshot: "0", Raw: []byte("0")})

	const goroutines = 8
	const iterations = 2000

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for w := 0; w < goroutines; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				store.Swap(&Versioned[string]{Version: "vN", Snapshot: "n", Raw: []byte("n")})
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				v, ok := store.Load()
				require.True(t, ok)
				require.NotNil(t, v)
				assert.NotEmpty(t, v.Version)
			}
		}()
	}
	wg.Wait()
}
