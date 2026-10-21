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

package configsyncrevocation

import "testing"

func TestSnapshot_Revoked(t *testing.T) {
	t.Parallel()
	snapshot := NewSnapshot(Revocations{
		JTIs: []JTIRevocation{{Scope: "gw-1", JTI: "j-revoked"}},
		Marks: []IssuedBeforeMark{
			{Scope: "gw-1", IssuedBefore: 1000},
			{Scope: "gw-2", IssuedBefore: 500},
			{Scope: "gw-2", IssuedBefore: 400},
		},
	})
	instance := func(scope, jti string, iat int64) Identity {
		return Identity{Scope: scope, JTI: jti, IssuedAt: iat, Signed: true, InstanceScoped: true}
	}

	cases := []struct {
		name       string
		id         Identity
		wantReason Reason
		wantOK     bool
	}{
		{"shared token is never revoked", Identity{}, "", false},
		{"unsigned identity with a matching scope is never revoked", Identity{Scope: "gw-1", JTI: "j-revoked", IssuedAt: 1}, "", false},
		{"legacy scope-only token is never revoked", Identity{Scope: "gw-1", JTI: "j-revoked", IssuedAt: 1, Signed: true}, "", false},
		{"revoked jti", instance("gw-1", "j-revoked", 2000), ReasonJTI, true},
		{"other jti of the same scope", instance("gw-1", "j-other", 2000), "", false},
		{"revoked jti under another scope", instance("gw-3", "j-revoked", 2000), "", false},
		{"iat before the mark", instance("gw-1", "j-other", 999), ReasonIssuedBefore, true},
		{"iat equal to the mark passes", instance("gw-1", "j-other", 1000), "", false},
		{"iat after the mark passes", instance("gw-1", "j-other", 1001), "", false},
		{"missing iat skips the mark", instance("gw-1", "j-other", 0), "", false},
		{"missing jti still checks the mark", instance("gw-1", "", 10), ReasonIssuedBefore, true},
		{"highest mark wins", instance("gw-2", "", 450), ReasonIssuedBefore, true},
		{"scope without revocations", instance("gw-9", "j-revoked", 1), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reason, ok := snapshot.Revoked(tc.id)
			if ok != tc.wantOK || reason != tc.wantReason {
				t.Fatalf("Revoked = (%q, %v), want (%q, %v)", reason, ok, tc.wantReason, tc.wantOK)
			}
		})
	}
}

func TestSnapshot_ZeroValueRevokesNothing(t *testing.T) {
	t.Parallel()
	var snapshot Snapshot
	id := Identity{Scope: "gw-1", JTI: "j", IssuedAt: 1, Signed: true, InstanceScoped: true}
	if reason, ok := snapshot.Revoked(id); ok {
		t.Fatalf("zero snapshot revoked the token with reason %q", reason)
	}
	if jtis, marks := snapshot.Len(); jtis != 0 || marks != 0 {
		t.Fatalf("Len = (%d, %d), want (0, 0)", jtis, marks)
	}
}
