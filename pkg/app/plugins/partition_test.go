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

package plugins

import (
	"strings"
	"testing"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

func TestParseGroupBy(t *testing.T) {
	valid := []struct {
		mode, claim, header string
		want                GroupBy
	}{
		{"", "", "", GroupBy{}},
		{"", "", "X-User", GroupBy{Mode: GroupByHeader, Header: "X-User"}},
		{" Subject ", "", "", GroupBy{Mode: GroupBySubject}},
		{"claim", " oid ", "", GroupBy{Mode: GroupByClaim, Claim: "oid"}},
		{"header", "", "X-User", GroupBy{Mode: GroupByHeader, Header: "X-User"}},
	}
	for _, tc := range valid {
		got, err := ParseGroupBy(tc.mode, tc.claim, tc.header)
		if err != nil || got != tc.want {
			t.Errorf("ParseGroupBy(%q, %q, %q) = %+v, %v; want %+v", tc.mode, tc.claim, tc.header, got, err, tc.want)
		}
	}
	invalid := [][3]string{
		{"", "oid", ""},
		{"subject", "oid", ""},
		{"subject", "", "X-User"},
		{"claim", "", ""},
		{"claim", "bad claim", ""},
		{"claim", strings.Repeat("c", maxGroupByNameLength+1), ""},
		{"claim", "oid", "X-User"},
		{"header", "", ""},
		{"header", "oid", "X-User"},
		{"ip", "", ""},
	}
	for _, tc := range invalid {
		if _, err := ParseGroupBy(tc[0], tc[1], tc[2]); err == nil {
			t.Errorf("ParseGroupBy(%q, %q, %q) accepted", tc[0], tc[1], tc[2])
		}
	}
}

func TestGroupByKeySuffix(t *testing.T) {
	req := &infracontext.RequestContext{
		Headers:       map[string][]string{"X-User": {"u:1"}},
		CallerSubject: "spiffe://corp/agent:a",
		CallerClaims:  map[string]any{"oid": "o-1", "roles": []any{"a"}, "ver": float64(2), "empty": ""},
	}
	cases := []struct {
		g    GroupBy
		want string
	}{
		{GroupBy{}, ""},
		{GroupBy{Mode: GroupByHeader, Header: "x-user"}, ":hdr:u:1"},
		{GroupBy{Mode: GroupByHeader, Header: "X-Missing"}, ""},
		{GroupBy{Mode: GroupBySubject}, ":sub:spiffe%3A%2F%2Fcorp%2Fagent%3Aa"},
		{GroupBy{Mode: GroupByClaim, Claim: "oid"}, ":clm:oid:o-1"},
		{GroupBy{Mode: GroupByClaim, Claim: "ver"}, ":clm:ver:2"},
		{GroupBy{Mode: GroupByClaim, Claim: "roles"}, ""},
		{GroupBy{Mode: GroupByClaim, Claim: "empty"}, ""},
		{GroupBy{Mode: GroupByClaim, Claim: "missing"}, ""},
	}
	for _, tc := range cases {
		if got := tc.g.KeySuffix(req); got != tc.want {
			t.Errorf("%+v: KeySuffix = %q, want %q", tc.g, got, tc.want)
		}
	}
	if got := (GroupBy{Mode: GroupBySubject}).KeySuffix(&infracontext.RequestContext{}); got != "" {
		t.Errorf("anonymous request: KeySuffix = %q, want shared counter", got)
	}
	long := &infracontext.RequestContext{CallerSubject: strings.Repeat("s", maxPartitionValueLength+1)}
	got := GroupBy{Mode: GroupBySubject}.KeySuffix(long)
	if !strings.HasPrefix(got, ":sub:h") || len(got) != len(":sub:h")+64 {
		t.Errorf("a long subject must be keyed by its digest, got %q", got)
	}
}
