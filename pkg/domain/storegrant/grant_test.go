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

package storegrant

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestNewNormalisesAndValidates(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	g, err := New(gw, " github ", ids.RegistryID{}, []string{"sre", " eng", "sre", ""}, []string{"bob", "ana", "bob"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.CatalogCode != "github" || g.IsInstance() {
		t.Fatalf("code must be trimmed and the grant code-level, got %+v", g)
	}
	if len(g.Groups) != 2 || g.Groups[0] != "eng" || g.Groups[1] != "sre" {
		t.Fatalf("groups must be trimmed, deduped and sorted, got %v", g.Groups)
	}
	if len(g.Users) != 2 || g.Users[0] != "ana" || g.Users[1] != "bob" {
		t.Fatalf("users must be deduped and sorted, got %v", g.Users)
	}
	if _, err := New(ids.GatewayID{}, "github", ids.RegistryID{}, nil, nil); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("nil gateway must be invalid, got %v", err)
	}
	if _, err := New(gw, "  ", ids.RegistryID{}, nil, nil); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("empty code must be invalid, got %v", err)
	}
}

func TestAllowsIsExplicit(t *testing.T) {
	g := &Grant{Groups: []string{"sre"}, Users: []string{"ana"}}
	if !g.Allows(nil, "ana") || !g.Allows([]string{"eng", "sre"}, "bob") {
		t.Fatal("subject in users or a group in groups must be allowed")
	}
	if g.Allows([]string{"eng"}, "bob") || g.Allows(nil, "") {
		t.Fatal("a principal named by neither axis must not be allowed")
	}
	var empty *Grant
	if empty.Allows([]string{"sre"}, "ana") || (&Grant{}).Allows([]string{"sre"}, "ana") {
		t.Fatal("a nil or empty grant is granted to nobody")
	}
}

func TestAddUser(t *testing.T) {
	g := &Grant{Users: []string{"bob"}}
	if !g.AddUser(" ana ") || len(g.Users) != 2 || g.Users[0] != "ana" {
		t.Fatalf("AddUser must add and keep order, got %v", g.Users)
	}
	if g.AddUser("ana") || g.AddUser("") {
		t.Fatal("re-adding or adding an empty subject must be a no-op")
	}
}

func TestSetIndexesCodeAndInstanceGrants(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	finance := ids.New[ids.RegistryKind]()
	analytics := ids.New[ids.RegistryKind]()
	code, _ := New(gw, "snowflake", ids.RegistryID{}, []string{"eng"}, nil)
	inst, _ := New(gw, "snowflake", finance, []string{"finance"}, nil)
	empty, _ := New(gw, "github", ids.RegistryID{}, nil, nil)
	set := Index([]*Grant{code, inst, empty, nil})

	if set.Code("github") != nil {
		t.Fatal("an empty grant must be indexed as absent")
	}
	if !set.CodeAllows("snowflake", []string{"eng"}, "x") || set.CodeAllows("snowflake", []string{"finance"}, "x") {
		t.Fatal("CodeAllows must consult the code-level grant only")
	}
	if !set.InstanceAllows("snowflake", finance, []string{"finance"}, "x") {
		t.Fatal("an instance grant must admit on that instance")
	}
	if set.InstanceAllows("snowflake", analytics, []string{"finance"}, "x") {
		t.Fatal("an instance grant must not admit on another instance")
	}
	if !set.InstanceAllows("snowflake", analytics, []string{"eng"}, "x") {
		t.Fatal("the code-level grant admits on every instance")
	}
	if !set.AnyInstanceAllows("snowflake", []string{"finance"}, "x") || set.AnyInstanceAllows("snowflake", []string{"eng"}, "x") {
		t.Fatal("AnyInstanceAllows must look at instance grants only")
	}
	var nilSet *Set
	if nilSet.CodeAllows("snowflake", []string{"eng"}, "x") || nilSet.InstanceAllows("snowflake", finance, nil, "x") {
		t.Fatal("a nil set grants nothing")
	}
}

func TestGrantJSONRoundTrip(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	g, _ := New(gw, "snowflake", reg, []string{"finance"}, []string{"ana"})
	raw, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Grant
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.GatewayID != gw || back.RegistryID != reg || back.CatalogCode != "snowflake" || back.Users[0] != "ana" {
		t.Fatalf("round trip lost data: %+v", back)
	}
	// A code-level grant omits registry_id on the wire.
	code, _ := New(gw, "github", ids.RegistryID{}, nil, []string{"ana"})
	raw, _ = json.Marshal(code)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if _, present := m["registry_id"]; present {
		t.Fatalf("code-level grant must omit registry_id, got %s", raw)
	}
}
