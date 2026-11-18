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
	"errors"
	"slices"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestNewAgentAccessValidates(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	cases := []struct {
		name          string
		gw            ids.GatewayID
		principalType PrincipalType
		principalID   string
		mode          string
		ok            bool
	}{
		{"all row", gw, PrincipalAll, "", "all", true},
		{"all row with an id", gw, PrincipalAll, "ana", "all", false},
		{"group row", gw, PrincipalGroup, "eng", " Selected ", true},
		{"group row without an id", gw, PrincipalGroup, " ", "none", false},
		{"user row", gw, PrincipalUser, "ana", "none", true},
		{"unknown type", gw, PrincipalType("team"), "x", "all", false},
		{"unknown mode", gw, PrincipalUser, "ana", "open", false},
		{"no gateway", ids.GatewayID{}, PrincipalAll, "", "all", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAgentAccess(tc.gw, tc.principalType, tc.principalID, tc.mode, []ids.RegistryID{reg})
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalidAgentAccess) {
				t.Fatalf("expected ErrInvalidAgentAccess, got %v", err)
			}
		})
	}
}

func TestNewAgentAccessKeepsRegistriesOnlyWhenSelected(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	a, b := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	selected, err := NewAgentAccess(gw, PrincipalGroup, "eng", "selected", []ids.RegistryID{b, a, b, {}})
	if err != nil {
		t.Fatal(err)
	}
	want := []ids.RegistryID{a, b}
	slices.SortFunc(want, func(x, y ids.RegistryID) int {
		if x.String() < y.String() {
			return -1
		}
		return 1
	})
	if !slices.Equal(selected.RegistryIDs, want) {
		t.Fatalf("registry ids = %v, want %v", selected.RegistryIDs, want)
	}
	all, err := NewAgentAccess(gw, PrincipalAll, "", "all", []ids.RegistryID{a})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.RegistryIDs) != 0 {
		t.Fatalf("all keeps no registry ids, got %v", all.RegistryIDs)
	}
}

func TestAgentsFor(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	a, b, c := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	gone := ids.New[ids.RegistryKind]()
	agents := []ids.RegistryID{a, b, c}
	row := func(pt PrincipalType, id, mode string, regs ...ids.RegistryID) *AgentAccess {
		r, err := NewAgentAccess(gw, pt, id, mode, regs)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	cases := []struct {
		name    string
		rows    []*AgentAccess
		subject string
		groups  []string
		want    []ids.RegistryID
	}{
		{"no rows", nil, "ana", []string{"eng"}, nil},
		{"all row", []*AgentAccess{row(PrincipalAll, "", "all")}, "ana", nil, agents},
		{"own none beats everything", []*AgentAccess{
			row(PrincipalUser, "ana", "none"), row(PrincipalAll, "", "all"), row(PrincipalGroup, "eng", "all"),
		}, "ana", []string{"eng"}, nil},
		{"group none without own row", []*AgentAccess{
			row(PrincipalGroup, "contractors", "none"), row(PrincipalGroup, "eng", "all"), row(PrincipalAll, "", "all"),
		}, "ana", []string{"eng", "contractors"}, nil},
		{"own row overrides group none", []*AgentAccess{
			row(PrincipalUser, "ana", "selected", b), row(PrincipalGroup, "contractors", "none"),
		}, "ana", []string{"contractors"}, []ids.RegistryID{b}},
		{"union of own, groups and all", []*AgentAccess{
			row(PrincipalUser, "ana", "selected", c), row(PrincipalGroup, "eng", "selected", a), row(PrincipalAll, "", "selected", b),
		}, "ana", []string{"eng"}, agents},
		{"selected ignores agents that are not enabled", []*AgentAccess{
			row(PrincipalGroup, "eng", "selected", gone, b),
		}, "ana", []string{"eng"}, []ids.RegistryID{b}},
		{"other people's rows do not apply", []*AgentAccess{
			row(PrincipalUser, "bob", "all"), row(PrincipalGroup, "sales", "all"),
		}, "ana", []string{"eng"}, nil},
		{"group key goes by groups and all", []*AgentAccess{
			row(PrincipalUser, "ana", "none"), row(PrincipalGroup, "eng", "selected", a), row(PrincipalAll, "", "selected", c),
		}, "", []string{"eng"}, []ids.RegistryID{a, c}},
		{"group key with a group on none", []*AgentAccess{
			row(PrincipalGroup, "eng", "none"), row(PrincipalAll, "", "all"),
		}, "", []string{"eng"}, nil},
		{"none on all adds nothing", []*AgentAccess{
			row(PrincipalAll, "", "none"), row(PrincipalGroup, "eng", "selected", a),
		}, "ana", []string{"eng"}, []ids.RegistryID{a}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AgentsFor(tc.rows, tc.subject, tc.groups, agents)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("AgentsFor = %v, want %v", got, tc.want)
			}
		})
	}
}
