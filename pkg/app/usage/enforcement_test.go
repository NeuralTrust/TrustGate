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
	"fmt"
	"sync"
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

func TestEnforcementKeepsANewerBlockAgainstAnOlderList(t *testing.T) {
	t.Parallel()
	e := NewEnforcement()
	e.ApplySnapshot(domain.Snapshot{Exhausted: []domain.TenantState{exhausted(t, "y", 50)}, AsOfVersion: 50})
	e.ApplySnapshot(domain.Snapshot{AsOfVersion: 40})
	if _, ok := e.Exhausted("y"); !ok {
		t.Fatal("an older list unblocked y")
	}
}

func TestEnforcementReadsWhileSnapshotsApply(t *testing.T) {
	t.Parallel()
	e := NewEnforcement()
	e.ApplySnapshot(domain.Snapshot{Exhausted: []domain.TenantState{exhausted(t, "stable", 1)}, AsOfVersion: 1})

	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan string, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, ok := e.Exhausted("stable"); !ok {
					errs <- "stable read as healthy mid-apply"
					return
				}
			}
		}()
	}
	for v := int64(2); v < 200; v++ {
		e.ApplySnapshot(domain.Snapshot{
			Exhausted:   []domain.TenantState{exhausted(t, "stable", 1), exhausted(t, fmt.Sprintf("t%d", v), v)},
			AsOfVersion: v,
		})
	}
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if _, ok := e.Exhausted("t199"); !ok {
		t.Fatal("last snapshot not applied")
	}
	if _, ok := e.Exhausted("t100"); ok {
		t.Fatal("t100 still exhausted after it left the list")
	}
}
