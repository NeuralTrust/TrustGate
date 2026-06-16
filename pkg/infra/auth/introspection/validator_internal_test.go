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

package introspection

import (
	"testing"
	"time"
)

func TestSweepLocked_DropsExpiredEntries(t *testing.T) {
	t.Parallel()
	v := NewValidator(nil)
	now := time.Now()
	v.cache["dead"] = cacheEntry{expiresAt: now.Add(-time.Second)}
	v.cache["live"] = cacheEntry{expiresAt: now.Add(time.Minute)}
	v.lastSweep = now.Add(-2 * sweepInterval)

	v.mu.Lock()
	v.sweepLocked()
	v.mu.Unlock()

	if _, ok := v.cache["dead"]; ok {
		t.Fatal("expired entry not purged")
	}
	if _, ok := v.cache["live"]; !ok {
		t.Fatal("live entry must survive the sweep")
	}
}

func TestSweepLocked_RateLimited(t *testing.T) {
	t.Parallel()
	v := NewValidator(nil)
	now := time.Now()
	v.cache["dead"] = cacheEntry{expiresAt: now.Add(-time.Second)}
	v.lastSweep = now

	v.mu.Lock()
	v.sweepLocked()
	v.mu.Unlock()

	if _, ok := v.cache["dead"]; !ok {
		t.Fatal("sweep must not run again within sweepInterval")
	}
}
