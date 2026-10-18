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

package modules

import (
	"testing"
	"time"

	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

func TestSnapshotStandInAllowed(t *testing.T) {
	window := 2 * time.Minute
	if !snapshotStandInAllowed(nil, window) {
		t.Fatal("no snapshot tracker is not a stale snapshot")
	}

	lkg := configsync.NewSnapshotStatus(nil)
	lkg.MarkLKG("v1", time.Second)
	if snapshotStandInAllowed(lkg, window) {
		t.Fatal("last-known-good must not be bridged from the catalog")
	}

	none := configsync.NewSnapshotStatus(nil)
	if snapshotStandInAllowed(none, window) {
		t.Fatal("a pod with no snapshot must not invent a registry")
	}

	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	at := now
	live := configsync.NewSnapshotStatus(func() time.Time { return at })
	at = now.Add(-time.Second)
	live.MarkLive("v2")
	at = now
	if !snapshotStandInAllowed(live, window) {
		t.Fatal("a live snapshot inside the window may be bridged")
	}

	at = now.Add(-window - time.Second)
	stale := configsync.NewSnapshotStatus(func() time.Time { return at })
	stale.MarkLive("v3")
	at = now
	if snapshotStandInAllowed(stale, window) {
		t.Fatal("a live snapshot whose last converge is older than the window must not be bridged")
	}

	at = now.Add(-10 * time.Minute)
	quiet := configsync.NewSnapshotStatus(func() time.Time { return at })
	quiet.MarkLive("v4")
	at = now
	quiet.ConfirmLive()
	if !snapshotStandInAllowed(quiet, window) {
		t.Fatal("a live snapshot converged just now may be bridged even though it was applied long ago")
	}
	age, ok := quiet.Age()
	if !ok || age < 10*time.Minute {
		t.Fatalf("a not-modified converge reset snapshot age to %s", age)
	}
}
