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

package usage

import (
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

func exhausted(t *testing.T, tenant string, version int64) domain.TenantState {
	t.Helper()
	return state(t, tenant, true, version)
}

func TestEnforcementAppliesNewerAndDropsOlder(t *testing.T) {
	t.Parallel()
	e := NewEnforcement()
	if e.Received() {
		t.Fatal("received before any snapshot")
	}
	e.ApplySnapshot(domain.Snapshot{Exhausted: []domain.TenantState{exhausted(t, "a", 5)}, AsOfVersion: 5})
	if !e.Received() {
		t.Fatal("not received after a snapshot")
	}
	if reason, ok := e.Exhausted("a"); !ok || reason != domain.ReasonWalletEmpty {
		t.Fatalf("a = %v %v, want exhausted wallet_empty", reason, ok)
	}
	if _, ok := e.Exhausted("unknown"); ok {
		t.Fatal("unknown tenant reported exhausted")
	}
}

// A replica that unblocked tenant x (x missing, as of 110) followed by a stale
// replica that still lists x at 105 must not block x again.
func TestEnforcementTombstoneSurvivesAStaleReplica(t *testing.T) {
	t.Parallel()
	e := NewEnforcement()
	e.ApplySnapshot(domain.Snapshot{Exhausted: []domain.TenantState{exhausted(t, "x", 100)}, AsOfVersion: 100})
	e.ApplySnapshot(domain.Snapshot{AsOfVersion: 110})
	if _, ok := e.Exhausted("x"); ok {
		t.Fatal("x still exhausted after the unblock")
	}
	e.ApplySnapshot(domain.Snapshot{Exhausted: []domain.TenantState{exhausted(t, "x", 105)}, AsOfVersion: 105})
	if _, ok := e.Exhausted("x"); ok {
		t.Fatal("a stale replica blocked x again")
	}
	e.ApplySnapshot(domain.Snapshot{Exhausted: []domain.TenantState{exhausted(t, "x", 120)}, AsOfVersion: 120})
	if _, ok := e.Exhausted("x"); !ok {
		t.Fatal("a newer block was ignored")
	}
}

// A snapshot that is behind the data plane must not unblock a tenant the data
// plane knows to be exhausted at a newer version.
func TestEnforcementKeepsANewerBlockAgainstAnOlderList(t *testing.T) {
	t.Parallel()
	e := NewEnforcement()
	e.ApplySnapshot(domain.Snapshot{Exhausted: []domain.TenantState{exhausted(t, "y", 50)}, AsOfVersion: 50})
	e.ApplySnapshot(domain.Snapshot{AsOfVersion: 40})
	if _, ok := e.Exhausted("y"); !ok {
		t.Fatal("an older list unblocked y")
	}
}
