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

package client

import (
	"container/list"
	"fmt"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

func TestCachedDialerStoreEnforcesCapacity(t *testing.T) {
	d := &cachedDialer{entries: map[string]*sessionEntry{}, lru: list.New()}
	now := time.Now()
	var evicted []*Session
	for i := range maxCachedSessions + 25 {
		evicted = append(evicted, d.storeLocked(fmt.Sprintf("key-%d", i), &Session{}, now.Add(time.Duration(i)))...)
	}
	if got := len(d.entries); got != maxCachedSessions {
		t.Fatalf("entries = %d, want %d", got, maxCachedSessions)
	}
	if got := len(evicted); got != 25 {
		t.Fatalf("evicted = %d, want 25", got)
	}
	if _, ok := d.entries["key-0"]; ok {
		t.Fatal("oldest entry was retained")
	}
	if _, ok := d.entries[fmt.Sprintf("key-%d", maxCachedSessions+24)]; !ok {
		t.Fatal("newest entry was evicted")
	}
}

func TestSessionCacheKeyIncludesConnectionIdentity(t *testing.T) {
	base := appmcp.Target{URL: "https://a.example/mcp", PinKey: "pin", Revision: "one"}
	cases := []appmcp.Target{
		{URL: "https://b.example/mcp", PinKey: "pin", Revision: "one"},
		{URL: base.URL, PinKey: "pin", Revision: "two"},
		{URL: base.URL, PinKey: "other", Revision: "one"},
		{URL: base.URL, PinKey: "pin", Revision: "one", Headers: map[string]string{"Authorization": "Bearer token"}},
		{URL: base.URL, PinKey: "pin", Revision: "one", RestrictPrivateNetwork: true},
	}
	baseKey := sessionCacheKey(base)
	for i, target := range cases {
		if got := sessionCacheKey(target); got == baseKey {
			t.Fatalf("case %d produced the base cache key", i)
		}
	}
}

func TestCachedDialerStoreEvictsIdleEntries(t *testing.T) {
	d := &cachedDialer{entries: map[string]*sessionEntry{}, lru: list.New()}
	now := time.Now()
	d.storeLocked("stale", &Session{}, now.Add(-sessionIdleTTL-time.Second))
	evicted := d.storeLocked("fresh", &Session{}, now)
	if len(evicted) != 1 {
		t.Fatalf("evicted = %d, want one", len(evicted))
	}
	if _, ok := d.entries["stale"]; ok {
		t.Fatal("idle entry was retained")
	}
}
