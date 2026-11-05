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

package storeaccess

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func policySet(t *testing.T, gw ids.GatewayID, groups map[string]string, users map[string]string) *PolicySet {
	t.Helper()
	var all []*Policy
	for g, m := range groups {
		p, err := NewPolicy(gw, PrincipalGroup, g, m)
		if err != nil {
			t.Fatalf("NewPolicy: %v", err)
		}
		all = append(all, p)
	}
	for u, m := range users {
		p, err := NewPolicy(gw, PrincipalUser, u, m)
		if err != nil {
			t.Fatalf("NewPolicy: %v", err)
		}
		all = append(all, p)
	}
	return IndexPolicies(all)
}

func everyoneOf(t *testing.T, gw ids.GatewayID, mode string, excluded ...string) *Everyone {
	t.Helper()
	e, err := NewEveryone(gw, mode, []EveryoneGrant{{CatalogCode: "github"}}, excluded)
	if err != nil {
		t.Fatalf("NewEveryone: %v", err)
	}
	return e
}

func TestEveryoneReaches(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	policies := policySet(t, gw, map[string]string{"Sales": "none", "Eng": "curated"}, nil)
	e := everyoneOf(t, gw, "curated", "Contractors")

	cases := []struct {
		name   string
		groups []string
		want   bool
	}{
		{"excluded and passing group", []string{"Contractors", "Ops"}, true},
		{"only an excluded group", []string{"Contractors"}, false},
		{"only a group on none", []string{"Sales"}, false},
		{"group on none and a group with a policy", []string{"Sales", "Eng"}, true},
		{"group without a policy", []string{"Ops"}, true},
		{"no groups", nil, false},
		{"blank group", []string{" "}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := e.Reaches(tc.groups, policies); got != tc.want {
				t.Fatalf("Reaches(%v) = %v, want %v", tc.groups, got, tc.want)
			}
		})
	}
	var none *Everyone
	if none.Reaches([]string{"Ops"}, policies) {
		t.Fatal("no Everyone object reaches nobody")
	}
}

func TestResolveLevel(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	policies := policySet(t, gw,
		map[string]string{"Cur": "curated", "Open": "open", "None": "none"},
		map[string]string{"own-none": "none", "own-curated": "curated"})

	cases := []struct {
		name     string
		everyone string
		subject  string
		groups   []string
		fallback string
		want     string
	}{
		{"no everyone: own policy", "", "own-curated", []string{"Open"}, "open", "curated"},
		{"no everyone: group policy", "", "", []string{"Cur"}, "open", "curated"},
		{"no everyone: fallback", "", "", []string{"Plain"}, "none", "none"},
		{"own policy ignores everyone", "open", "own-curated", []string{"Plain"}, "curated", "curated"},
		{"own none blocks everyone", "open", "own-none", []string{"Plain"}, "curated", "none"},
		{"everyone raises a curated group", "open", "", []string{"Cur"}, "curated", "open"},
		{"everyone does not lower an open group", "curated", "", []string{"Open"}, "curated", "open"},
		{"everyone does not lower the fallback", "curated", "", []string{"Plain"}, "open", "open"},
		{"everyone raises the fallback", "curated", "", []string{"Plain"}, "none", "curated"},
		{"group on none does not reach everyone", "open", "", []string{"None"}, "curated", "none"},
		{"none group plus passing group", "open", "", []string{"None", "Plain"}, "curated", "open"},
		{"excluded group does not reach", "open", "", []string{"Excluded"}, "curated", "curated"},
		{"no groups never reach", "open", "someone", nil, "curated", "curated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var e *Everyone
			if tc.everyone != "" {
				e = everyoneOf(t, gw, tc.everyone, "Excluded")
			}
			if got := ResolveLevel(policies, e, tc.subject, tc.groups, tc.fallback); got != tc.want {
				t.Fatalf("ResolveLevel = %q, want %q", got, tc.want)
			}
			if tc.everyone != "" {
				return
			}
			legacy := policies.Mode(tc.subject, tc.groups)
			if legacy == "" {
				legacy = tc.fallback
			}
			if got := ResolveLevel(policies, nil, tc.subject, tc.groups, tc.fallback); got != legacy {
				t.Fatalf("without Everyone the level must equal today's %q, got %q", legacy, got)
			}
		})
	}
}

func TestSetWithEveryone(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	other := ids.New[ids.RegistryKind]()
	explicit, _ := New(gw, "jira", ids.RegistryID{}, []string{"Eng"}, nil)
	set := Index([]*Grant{explicit})
	e, err := NewEveryone(gw, "curated", []EveryoneGrant{{CatalogCode: "github"}, {CatalogCode: "snowflake", RegistryID: reg}}, []string{"Contractors"})
	if err != nil {
		t.Fatalf("NewEveryone: %v", err)
	}
	policies := policySet(t, gw, map[string]string{"Sales": "none"}, nil)
	with := set.WithEveryone(e, policies)

	reached := []string{"Ops"}
	if !with.CodeAllows("github", reached, "") || !with.InstanceAllows("github", other, reached, "") {
		t.Fatal("a code-level Everyone grant covers the code and every instance for a reached caller")
	}
	if !with.InstanceAllows("snowflake", reg, reached, "") || with.InstanceAllows("snowflake", other, reached, "") {
		t.Fatal("an instance-level Everyone grant covers that registry only")
	}
	if with.CodeAllows("snowflake", reached, "") || !with.AnyInstanceAllows("snowflake", reached, "") {
		t.Fatal("an instance-level Everyone grant is not a code grant but counts as some instance")
	}
	for _, groups := range [][]string{{"Contractors"}, {"Sales"}, nil} {
		if with.CodeAllows("github", groups, "ana") || with.AnyInstanceAllows("snowflake", groups, "ana") {
			t.Fatalf("callers that do not reach Everyone get nothing from it (groups %v)", groups)
		}
	}
	if !with.CodeAllows("jira", []string{"Eng"}, "") || with.CodeAllows("jira", reached, "") {
		t.Fatal("explicit grants keep working unchanged")
	}
	if set.CodeAllows("github", reached, "") {
		t.Fatal("WithEveryone must not change the original set")
	}
	if with.Code("github") != nil {
		t.Fatal("Code returns explicit grants only")
	}
	var nilSet *Set
	if !nilSet.WithEveryone(e, policies).CodeAllows("github", reached, "") {
		t.Fatal("a nil set with Everyone still grants Everyone's servers")
	}
}
