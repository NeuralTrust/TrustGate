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
	"encoding/json"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestNewEveryoneValidates(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	cases := []struct {
		name   string
		gw     ids.GatewayID
		mode   string
		grants []EveryoneGrant
		ok     bool
	}{
		{"open without grants", gw, "open", nil, true},
		{"curated with a grant", gw, " Curated ", []EveryoneGrant{{CatalogCode: "github"}}, true},
		{"curated without grants", gw, "curated", nil, false},
		{"none", gw, "none", nil, false},
		{"unknown mode", gw, "all", nil, false},
		{"no gateway", ids.GatewayID{}, "open", nil, false},
		{"empty code", gw, "curated", []EveryoneGrant{{CatalogCode: " "}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEveryone(tc.gw, tc.mode, tc.grants, nil)
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalidEveryone) {
				t.Fatalf("expected ErrInvalidEveryone, got %v", err)
			}
		})
	}
}

func TestNewEveryoneNormalises(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	e, err := NewEveryone(gw, "curated",
		[]EveryoneGrant{{CatalogCode: "snowflake", RegistryID: reg}, {CatalogCode: " github "}, {CatalogCode: "github"}},
		[]string{"Sales", " Contractors ", "Sales", ""})
	if err != nil {
		t.Fatalf("NewEveryone: %v", err)
	}
	if len(e.Grants) != 2 || e.Grants[0].CatalogCode != "github" || e.Grants[1].RegistryID != reg {
		t.Fatalf("grants must be de-duplicated and sorted, got %+v", e.Grants)
	}
	if len(e.ExcludedGroups) != 2 || e.ExcludedGroups[0] != "Contractors" || e.ExcludedGroups[1] != "Sales" {
		t.Fatalf("excluded groups must be trimmed, de-duplicated and sorted, got %v", e.ExcludedGroups)
	}
	if !e.Excludes(" Sales ") || e.Excludes("Engineering") {
		t.Fatal("Excludes must match trimmed group keys exactly")
	}
}

func TestEveryoneWithoutRegistry(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	e, _ := NewEveryone(gw, "curated", []EveryoneGrant{{CatalogCode: "github"}, {CatalogCode: "snowflake", RegistryID: reg}}, nil)

	out, changed := e.WithoutRegistry(reg)
	if !changed || len(out.Grants) != 1 || out.Grants[0].CatalogCode != "github" {
		t.Fatalf("the instance grant must go, got %+v changed=%v", out.Grants, changed)
	}
	if len(e.Grants) != 2 {
		t.Fatal("the original must not change")
	}
	if _, changed := e.WithoutRegistry(ids.New[ids.RegistryKind]()); changed {
		t.Fatal("an unrelated registry changes nothing")
	}
}

func TestEveryoneJSONRoundTrip(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	e, _ := NewEveryone(gw, "curated", []EveryoneGrant{{CatalogCode: "github"}, {CatalogCode: "snowflake", RegistryID: reg}}, []string{"Contractors"})

	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Everyone
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.GatewayID != gw || back.Mode != "curated" || len(back.Grants) != 2 || back.Grants[0].IsInstance() || back.Grants[1].RegistryID != reg || back.ExcludedGroups[0] != "Contractors" {
		t.Fatalf("round trip lost data: %+v", back)
	}
	var code map[string]any
	grant, err := json.Marshal(EveryoneGrant{CatalogCode: "github"})
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}
	if err := json.Unmarshal(grant, &code); err != nil {
		t.Fatalf("unmarshal grant: %v", err)
	}
	if _, present := code["registry_id"]; present {
		t.Fatalf("a code-level grant must omit registry_id, got %s", grant)
	}
}

func TestPolicySetGroupMode(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	none, _ := NewPolicy(gw, PrincipalGroup, "Sales", "none")
	set := IndexPolicies([]*Policy{none})
	if m, ok := set.GroupMode(" Sales "); !ok || m != "none" {
		t.Fatalf("expected Sales on none, got %q %v", m, ok)
	}
	if _, ok := set.GroupMode("Engineering"); ok {
		t.Fatal("a group without a policy has none")
	}
	var nilSet *PolicySet
	if _, ok := nilSet.GroupMode("Sales"); ok {
		t.Fatal("a nil set has no policies")
	}
}
