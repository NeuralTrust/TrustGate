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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	identitydomain "github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
)

func scoperUnderTest() RoleScoper {
	return NewRoleScoper(approle.NewOIDCResolver())
}

func rolePrincipalCtx(groups ...string) context.Context {
	values := make([]any, 0, len(groups))
	for _, g := range groups {
		values = append(values, g)
	}
	return identitydomain.WithPrincipal(context.Background(), &identitydomain.Principal{
		Subject: "user-1",
		Method:  identitydomain.MethodJWT,
		Claims:  map[string]any{"groups": values},
	})
}

func groupMapping(t *testing.T, group string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"match": "any",
		"claims": []map[string]any{
			{"path": "groups", "op": "contains_any", "values": []string{group}},
		},
	})
	if err != nil {
		t.Fatalf("marshal mapping: %v", err)
	}
	return raw
}

func roleMCPRegistry(t *testing.T, gw ids.GatewayID, name string) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(gw, name, "", &registrydomain.MCPTarget{URL: "http://upstream.local/mcp"})
	if err != nil {
		t.Fatalf("new mcp registry: %v", err)
	}
	return reg
}

func llmRegistry(t *testing.T, gw ids.GatewayID, name string) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewLLMRegistry(gw, name, "", &registrydomain.LLMTarget{
		Provider: "openai",
		Auth:     registrydomain.NewAPIKeyAuth("sk-test"),
	})
	if err != nil {
		t.Fatalf("new llm registry: %v", err)
	}
	return reg
}

func roleWith(t *testing.T, gw ids.GatewayID, name, group string, policies *roledomain.MCPPolicies, registries ...*registrydomain.Registry) *roledomain.Role {
	t.Helper()
	registryIDs := make([]ids.RegistryID, 0, len(registries))
	for _, reg := range registries {
		registryIDs = append(registryIDs, reg.ID)
	}
	role, err := roledomain.New(roledomain.CreateParams{
		GatewayID:   gw,
		Name:        name,
		OIDCMapping: groupMapping(t, group),
	})
	if err != nil {
		t.Fatalf("new role: %v", err)
	}
	role.RegistryIDs = registryIDs
	role.MCPPolicies = policies
	return role
}

func roleBasedSetup(
	t *testing.T,
	roles []*roledomain.Role,
	registries ...*registrydomain.Registry,
) (*appconsumer.RoutableConsumer, *appconsumer.Data) {
	t.Helper()
	gw := ids.New[ids.GatewayKind]()
	roleIDs := make([]ids.RoleID, 0, len(roles))
	for _, r := range roles {
		roleIDs = append(roleIDs, r.ID)
	}
	cons := &consumerdomain.Consumer{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gw,
		Name:        "virtual",
		Slug:        "virtual",
		Type:        consumerdomain.TypeMCP,
		RoutingMode: consumerdomain.RoutingModeRoleBased,
		RoleIDs:     roleIDs,
		Active:      true,
	}
	rc := appconsumer.RoutableConsumer{Consumer: cons}
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{rc}, roles)
	index := make(map[ids.RegistryID]*registrydomain.Registry, len(registries))
	for _, reg := range registries {
		index[reg.ID] = reg
	}
	data.SetRegistryIndex(index)
	return &data.Consumers[0], data
}

func TestRoleScoper_InlineConsumerPassesThrough(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Type: consumerdomain.TypeMCP,
	}}
	out, err := scoperUnderTest().Scope(context.Background(), rc, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out != rc {
		t.Fatal("inline consumer should pass through unchanged")
	}
}

func TestRoleScoper_NoPrincipalIsRejected(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg := roleMCPRegistry(t, gw, "srv")
	role := roleWith(t, gw, "ops", "ops-group", nil, reg)
	rc, data := roleBasedSetup(t, []*roledomain.Role{role}, reg)
	if _, err := scoperUnderTest().Scope(context.Background(), rc, data); !errors.Is(err, ErrNoRoleAccess) {
		t.Fatalf("err = %v, want ErrNoRoleAccess", err)
	}
}

func TestRoleScoper_NoMatchingRoleIsRejected(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg := roleMCPRegistry(t, gw, "srv")
	role := roleWith(t, gw, "ops", "ops-group", nil, reg)
	rc, data := roleBasedSetup(t, []*roledomain.Role{role}, reg)
	if _, err := scoperUnderTest().Scope(rolePrincipalCtx("other-group"), rc, data); !errors.Is(err, ErrNoRoleAccess) {
		t.Fatalf("err = %v, want ErrNoRoleAccess", err)
	}
}

func TestRoleScoper_RoleNotAssignedToConsumerIsRejected(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg := roleMCPRegistry(t, gw, "srv")
	role := roleWith(t, gw, "ops", "ops-group", nil, reg)
	rc, data := roleBasedSetup(t, []*roledomain.Role{role}, reg)
	rc.Consumer.RoleIDs = nil
	if _, err := scoperUnderTest().Scope(rolePrincipalCtx("ops-group"), rc, data); !errors.Is(err, ErrNoRoleAccess) {
		t.Fatalf("err = %v, want ErrNoRoleAccess", err)
	}
}

func TestRoleScoper_RoleWithOnlyLLMRegistriesIsRejected(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg := llmRegistry(t, gw, "llm")
	role := roleWith(t, gw, "ops", "ops-group", nil, reg)
	rc, data := roleBasedSetup(t, []*roledomain.Role{role}, reg)
	if _, err := scoperUnderTest().Scope(rolePrincipalCtx("ops-group"), rc, data); !errors.Is(err, ErrNoRoleAccess) {
		t.Fatalf("err = %v, want ErrNoRoleAccess", err)
	}
}

func TestRoleScoper_RoleWithoutToolkitGrantsRegistryViaWildcards(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	mcpReg := roleMCPRegistry(t, gw, "srv")
	llmReg := llmRegistry(t, gw, "llm")
	role := roleWith(t, gw, "ops", "ops-group", nil, mcpReg, llmReg)
	rc, data := roleBasedSetup(t, []*roledomain.Role{role}, mcpReg, llmReg)

	out, err := scoperUnderTest().Scope(rolePrincipalCtx("ops-group"), rc, data)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(out.Registries) != 1 || out.Registries[0].ID != mcpReg.ID {
		t.Fatalf("registries = %v, want only the MCP registry", out.Registries)
	}
	toolkit := out.Consumer.Toolkit()
	if len(toolkit) != 3 {
		t.Fatalf("toolkit = %v, want 3 wildcard entries", toolkit)
	}
	for _, e := range toolkit {
		if e.RegistryID != mcpReg.ID {
			t.Fatalf("toolkit entry registry = %s, want %s", e.RegistryID, mcpReg.ID)
		}
	}
	if out.Consumer.FailMode() != consumerdomain.FailModeClosed {
		t.Fatalf("fail mode = %q, want closed by default", out.Consumer.FailMode())
	}
	if rc.Consumer.MCP != nil {
		t.Fatal("original consumer must not be mutated")
	}
}

func TestRoleScoper_ExplicitEmptyToolkitDeniesAll(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	mcpReg := roleMCPRegistry(t, gw, "srv")
	role := roleWith(t, gw, "ops", "ops-group", &roledomain.MCPPolicies{
		Toolkit: consumerdomain.Toolkit{},
	}, mcpReg)
	rc, data := roleBasedSetup(t, []*roledomain.Role{role}, mcpReg)

	out, err := scoperUnderTest().Scope(rolePrincipalCtx("ops-group"), rc, data)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(out.Registries) != 1 || out.Registries[0].ID != mcpReg.ID {
		t.Fatalf("registries = %v, want the bound MCP registry", out.Registries)
	}
	if tk := out.Consumer.Toolkit(); len(tk) != 0 {
		t.Fatalf("toolkit = %v, want empty (explicit empty toolkit denies all)", tk)
	}
}

func TestRoleScoper_ExplicitToolkitIsFilteredToRoleMCPRegistries(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	mcpReg := roleMCPRegistry(t, gw, "srv")
	otherReg := roleMCPRegistry(t, gw, "other")
	role := roleWith(t, gw, "ops", "ops-group", &roledomain.MCPPolicies{
		Toolkit: consumerdomain.Toolkit{
			{RegistryID: mcpReg.ID, Tool: "search"},
			{RegistryID: otherReg.ID, Tool: "leak"},
		},
		FailMode: consumerdomain.FailModeOpen,
	}, mcpReg)
	rc, data := roleBasedSetup(t, []*roledomain.Role{role}, mcpReg, otherReg)

	out, err := scoperUnderTest().Scope(rolePrincipalCtx("ops-group"), rc, data)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	toolkit := out.Consumer.Toolkit()
	if len(toolkit) != 1 || toolkit[0].Tool != "search" || toolkit[0].RegistryID != mcpReg.ID {
		t.Fatalf("toolkit = %v, want only the search grant on the bound registry", toolkit)
	}
	if out.Consumer.FailMode() != consumerdomain.FailModeOpen {
		t.Fatalf("fail mode = %q, want open", out.Consumer.FailMode())
	}
}

func TestRoleScoper_MultipleRolesMergeGrantsAndClosedDominates(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	regA := roleMCPRegistry(t, gw, "srv-a")
	regB := roleMCPRegistry(t, gw, "srv-b")
	roleA := roleWith(t, gw, "ops", "ops-group", &roledomain.MCPPolicies{
		Toolkit:  consumerdomain.Toolkit{{RegistryID: regA.ID, Tool: "search"}},
		FailMode: consumerdomain.FailModeOpen,
	}, regA)
	roleB := roleWith(t, gw, "support", "ops-group", &roledomain.MCPPolicies{
		Toolkit: consumerdomain.Toolkit{{RegistryID: regB.ID, Tool: "fetch"}},
	}, regB)
	rc, data := roleBasedSetup(t, []*roledomain.Role{roleA, roleB}, regA, regB)

	out, err := scoperUnderTest().Scope(rolePrincipalCtx("ops-group"), rc, data)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(out.Registries) != 2 {
		t.Fatalf("registries = %d, want 2", len(out.Registries))
	}
	if len(out.Consumer.Toolkit()) != 2 {
		t.Fatalf("toolkit = %v, want both grants", out.Consumer.Toolkit())
	}
	if out.Consumer.FailMode() != consumerdomain.FailModeClosed {
		t.Fatalf("fail mode = %q, want closed (closed dominates)", out.Consumer.FailMode())
	}
}

func TestRoleScoper_AllRolesOpenYieldsOpen(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	regA := roleMCPRegistry(t, gw, "srv-a")
	regB := roleMCPRegistry(t, gw, "srv-b")
	roleA := roleWith(t, gw, "ops", "ops-group", &roledomain.MCPPolicies{
		Toolkit:  consumerdomain.Toolkit{{RegistryID: regA.ID, Tool: "search"}},
		FailMode: consumerdomain.FailModeOpen,
	}, regA)
	roleB := roleWith(t, gw, "support", "ops-group", &roledomain.MCPPolicies{
		Toolkit:  consumerdomain.Toolkit{{RegistryID: regB.ID, Tool: "fetch"}},
		FailMode: consumerdomain.FailModeOpen,
	}, regB)
	rc, data := roleBasedSetup(t, []*roledomain.Role{roleA, roleB}, regA, regB)

	out, err := scoperUnderTest().Scope(rolePrincipalCtx("ops-group"), rc, data)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Consumer.FailMode() != consumerdomain.FailModeOpen {
		t.Fatalf("fail mode = %q, want open", out.Consumer.FailMode())
	}
}
