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

package installation

import (
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const (
	instOld = "11111111-1111-4111-8111-111111111111"
	instMid = "22222222-2222-4222-8222-222222222222"
	instNew = "33333333-3333-4333-8333-333333333333"
	regA    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	regB    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

func TestFindRegistryIDOmitsANilID(t *testing.T) {
	if got := FindRegistryID(); !got.IsNil() {
		t.Fatalf("no id = %s, want nil", got)
	}
	if got := FindRegistryID(ids.RegistryID{}); !got.IsNil() {
		t.Fatalf("nil id = %s, want nil", got)
	}
	want := mustRegistryID(t, regA)
	if got := FindRegistryID(ids.RegistryID{}, want, mustRegistryID(t, regB)); got != want {
		t.Fatalf("scope = %s, want the first non-nil id %s", got, want)
	}
}

func TestSelectInstallationAcrossInstancesAndTimestamps(t *testing.T) {
	oldBoundA := installRow(t, instOld, regA, StatusInstalled, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	oldBoundA.Config = map[string]string{}
	newBoundA := installRow(t, instMid, regA, StatusInstalled, time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC))
	newBoundA.Config = map[string]string{"host": "just-written"}
	newerBoundB := installRow(t, instNew, regB, StatusInstalled, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	newerBoundB.Config = map[string]string{"host": "other-instance"}
	pendingA := installRow(t, "44444444-4444-4444-8444-444444444444", regA, StatusPendingApproval, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	unbound := installRow(t, "55555555-5555-4555-8555-555555555555", "", StatusInstalled, time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC))
	rows := []*Installation{oldBoundA, nil, newerBoundB, pendingA, newBoundA, unbound}

	scopeA := mustRegistryID(t, regA)
	if got := SelectInstallation(rows, ids.RegistryID{}); got != newerBoundB {
		t.Fatalf("unscoped = %s, want the newest installed row %s", idOf(got), newerBoundB.ID)
	}
	if got := SelectInstallation([]*Installation{oldBoundA, newBoundA}, ids.RegistryID{}); got != newBoundA {
		t.Fatalf("unscoped same registry = %s, want the row just written %s", idOf(got), newBoundA.ID)
	}
	if got := SelectInstallation(rows, scopeA); got != newBoundA {
		t.Fatalf("registry A = %s, want the newest installed row bound to A (%s), not %s", idOf(got), newBoundA.ID, newerBoundB.ID)
	}

	// The per-instance id is the installation id. It names that row even when a
	// different instance was written later.
	if got := SelectInstallation(rows, ids.From[ids.RegistryKind](oldBoundA.ID.UUID())); got != oldBoundA {
		t.Fatalf("instance %s = %s, want that row", oldBoundA.ID, idOf(got))
	}

	scopeMissing := mustRegistryID(t, "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	if got := SelectInstallation(rows, scopeMissing); got != unbound {
		t.Fatalf("unknown registry = %s, want the unbound canonical row %s", idOf(got), unbound.ID)
	}
	if got := SelectInstallation([]*Installation{newerBoundB, oldBoundA}, scopeMissing); got != nil {
		t.Fatalf("no unbound row and no match = %s, want nil", idOf(got))
	}
}

func TestSelectInstallationPrefersInstalledOverANewerPendingRow(t *testing.T) {
	installed := installRow(t, instOld, regA, StatusInstalled, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	pending := installRow(t, instNew, regA, StatusPendingApproval, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	revoked := installRow(t, instMid, regA, StatusRevoked, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	if got := SelectInstallation([]*Installation{pending, revoked, installed}, ids.RegistryID{}); got != installed {
		t.Fatalf("unscoped = %s, want the installed row", idOf(got))
	}
	if got := SelectInstallation([]*Installation{pending, revoked}, mustRegistryID(t, regA)); got != pending {
		t.Fatalf("no installed row = %s, want the newest eligible row", idOf(got))
	}
}

func TestSelectInstallationBreaksTimestampTiesByID(t *testing.T) {
	when := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	lower := installRow(t, instOld, regA, StatusInstalled, when)
	higher := installRow(t, instNew, regA, StatusInstalled, when)
	if got := SelectInstallation([]*Installation{lower, higher}, ids.RegistryID{}); got != higher {
		t.Fatalf("tie = %s, want %s", idOf(got), higher.ID)
	}
}

func TestSelectInstallationPrefersTheMatchingRowOverANewerUnboundOne(t *testing.T) {
	match := installRow(t, instOld, regA, StatusInstalled, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	unbound := installRow(t, instNew, "", StatusInstalled, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	if got := SelectInstallation([]*Installation{unbound, match}, mustRegistryID(t, regA)); got != match {
		t.Fatalf("scoped = %s, want the row bound to the registry", idOf(got))
	}
}

func TestSelectInstallationDoesNotPreferARevokedMatchOverALiveUnboundRow(t *testing.T) {
	revoked := installRow(t, instNew, regA, StatusRevoked, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	live := installRow(t, instOld, "", StatusInstalled, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if got := SelectInstallation([]*Installation{revoked, live}, mustRegistryID(t, regA)); got != live {
		t.Fatalf("scoped = %s, want the installed unbound row", idOf(got))
	}
}

func installRow(t *testing.T, id, registry string, status Status, created time.Time) *Installation {
	t.Helper()
	row := &Installation{
		ID:           mustInstallationID(t, id),
		Status:       status,
		CreatedAt:    created,
		CatalogCode:  "com.example/mcp",
		PrincipalSub: "ana",
	}
	if registry != "" {
		row.RegistryID = mustRegistryID(t, registry)
	}
	return row
}

func mustInstallationID(t *testing.T, raw string) ids.InstallationID {
	t.Helper()
	id, err := ids.Parse[ids.InstallationKind](raw)
	if err != nil {
		t.Fatalf("installation id %q: %v", raw, err)
	}
	return id
}

func mustRegistryID(t *testing.T, raw string) ids.RegistryID {
	t.Helper()
	id, err := ids.Parse[ids.RegistryKind](raw)
	if err != nil {
		t.Fatalf("registry id %q: %v", raw, err)
	}
	return id
}

func idOf(row *Installation) string {
	if row == nil {
		return "<nil>"
	}
	return row.ID.String()
}
