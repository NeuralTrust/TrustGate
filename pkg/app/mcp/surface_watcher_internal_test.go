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

package mcp

import (
	"fmt"
	"testing"
	"time"
)

func TestSurfaceWatcherCacheIsBoundedAndLRU(t *testing.T) {
	w := NewSurfaceWatcher(nil, nil).(*surfaceWatcher)
	now := time.Now()
	for i := range maxSurfaceWatchEntries {
		w.storeSnapshot(fmt.Sprintf("key-%d", i), "value", now)
	}
	if _, ok := w.cachedSnapshot("key-0"); !ok {
		t.Fatal("expected oldest entry before capacity is exceeded")
	}
	w.storeSnapshot("extra", "value", now)

	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.cache) != maxSurfaceWatchEntries {
		t.Fatalf("cache size = %d, want %d", len(w.cache), maxSurfaceWatchEntries)
	}
	if _, ok := w.cache["key-0"]; !ok {
		t.Fatal("recently used entry was evicted")
	}
	if _, ok := w.cache["key-1"]; ok {
		t.Fatal("least recently used entry was retained")
	}
}

func TestSurfaceWatcherCacheRemovesExpiredEntries(t *testing.T) {
	w := NewSurfaceWatcher(nil, nil).(*surfaceWatcher)
	w.storeSnapshot("expired", "value", time.Now().Add(-2*surfaceWatchTTL))
	if _, ok := w.cachedSnapshot("expired"); ok {
		t.Fatal("expired entry was returned")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.cache) != 0 || w.lru.Len() != 0 {
		t.Fatal("expired entry was not removed from cache and LRU")
	}
}
