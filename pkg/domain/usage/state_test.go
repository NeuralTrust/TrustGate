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
	"errors"
	"testing"
)

func TestNewTenantState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		tenant     string
		status     Status
		reason     Reason
		version    int64
		wantErr    bool
		wantReason Reason
	}{
		{name: "exhausted wallet", tenant: "t1", status: StatusExhausted, reason: ReasonWalletEmpty, version: 3, wantReason: ReasonWalletEmpty},
		{name: "exhausted free limit", tenant: "t1", status: StatusExhausted, reason: ReasonFreeLimitReached, version: 3, wantReason: ReasonFreeLimitReached},
		{name: "healthy drops reason", tenant: "t1", status: StatusHealthy, reason: ReasonWalletEmpty, version: 3, wantReason: ReasonNone},
		{name: "missing tenant", status: StatusHealthy, version: 1, wantErr: true},
		{name: "zero version", tenant: "t1", status: StatusHealthy, wantErr: true},
		{name: "exhausted without reason", tenant: "t1", status: StatusExhausted, version: 1, wantErr: true},
		{name: "unknown status", tenant: "t1", status: Status("paused"), version: 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NewTenantState(tt.tenant, tt.status, tt.reason, tt.version)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidState) {
					t.Fatalf("err = %v, want ErrInvalidState", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewTenantState: %v", err)
			}
			if got.Reason != tt.wantReason || got.Exhausted() != (tt.status == StatusExhausted) {
				t.Fatalf("state = %+v", got)
			}
		})
	}
}

func TestSnapshotChanges(t *testing.T) {
	t.Parallel()
	exhausted := func(tenant string, version int64) TenantState {
		return TenantState{TenantID: tenant, Status: StatusExhausted, Reason: ReasonWalletEmpty, Version: version}
	}
	healthy := func(tenant string, version int64) TenantState {
		return TenantState{TenantID: tenant, Status: StatusHealthy, Version: version}
	}
	held := map[string]TenantState{
		"stale":   exhausted("stale", 5),
		"newer":   exhausted("newer", 50),
		"listed":  exhausted("listed", 8),
		"healthy": healthy("healthy", 3),
	}
	snapshot := Snapshot{
		AsOfVersion: 20,
		Exhausted:   []TenantState{exhausted("listed", 7), exhausted("fresh", 12), exhausted("fresh", 11)},
	}

	got := snapshot.Changes(held)

	want := []TenantState{exhausted("fresh", 12), healthy("stale", 20)}
	if len(got) != len(want) {
		t.Fatalf("changes = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("changes = %+v, want %+v", got, want)
		}
	}
	if held["stale"].Version != 5 {
		t.Fatal("Changes wrote into held")
	}
}

func TestTenantStateSupersedes(t *testing.T) {
	t.Parallel()
	exhausted := func(v int64) TenantState {
		return TenantState{TenantID: "t", Status: StatusExhausted, Reason: ReasonWalletEmpty, Version: v}
	}
	healthy := func(v int64) TenantState { return TenantState{TenantID: "t", Status: StatusHealthy, Version: v} }
	tests := []struct {
		name     string
		incoming TenantState
		held     TenantState
		want     bool
	}{
		{name: "newer version", incoming: healthy(5), held: exhausted(4), want: true},
		{name: "older version", incoming: healthy(3), held: exhausted(4), want: false},
		{name: "unblock wins a tie", incoming: healthy(4), held: exhausted(4), want: true},
		{name: "block loses a tie", incoming: exhausted(4), held: healthy(4), want: false},
		{name: "same state at the same version", incoming: exhausted(4), held: exhausted(4), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.incoming.Supersedes(tt.held); got != tt.want {
				t.Fatalf("Supersedes = %v, want %v", got, tt.want)
			}
		})
	}
}
