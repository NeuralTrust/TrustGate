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

package store

import (
	"context"
	"errors"
	"slices"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

type agentAccessKey struct {
	gw  ids.GatewayID
	pt  storeaccessdomain.PrincipalType
	pid string
}

type fakeAgentAccessRepo struct {
	rows    map[agentAccessKey]*storeaccessdomain.AgentAccess
	deleted []agentAccessKey
	pruned  []ids.RegistryID
}

func (f *fakeAgentAccessRepo) ListAgentAccessByGateway(_ context.Context, gw ids.GatewayID) ([]*storeaccessdomain.AgentAccess, error) {
	var out []*storeaccessdomain.AgentAccess
	for k, row := range f.rows {
		if k.gw == gw {
			out = append(out, row)
		}
	}
	return out, nil
}

func (f *fakeAgentAccessRepo) ListAgentAccess(context.Context, int, int) ([]*storeaccessdomain.AgentAccess, int, error) {
	return nil, 0, nil
}

func (f *fakeAgentAccessRepo) UpsertAgentAccess(_ context.Context, a *storeaccessdomain.AgentAccess) error {
	if f.rows == nil {
		f.rows = map[agentAccessKey]*storeaccessdomain.AgentAccess{}
	}
	f.rows[agentAccessKey{a.GatewayID, a.PrincipalType, a.PrincipalID}] = a
	return nil
}

func (f *fakeAgentAccessRepo) DeleteAgentAccess(_ context.Context, gw ids.GatewayID, pt storeaccessdomain.PrincipalType, pid string) error {
	k := agentAccessKey{gw, pt, pid}
	f.deleted = append(f.deleted, k)
	delete(f.rows, k)
	return nil
}

func (f *fakeAgentAccessRepo) PruneAgentRegistry(_ context.Context, _ ids.GatewayID, registryID ids.RegistryID) error {
	f.pruned = append(f.pruned, registryID)
	return nil
}

func TestAgentAccessServiceSet(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	agent := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, Type: registrydomain.TypeA2A}
	mcp := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, Type: registrydomain.TypeMCP}
	foreign := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: ids.New[ids.GatewayKind](), Type: registrydomain.TypeA2A}
	repo := &fakeAgentAccessRepo{}
	sig := &countingSignaler{}
	svc, err := NewAgentAccessService(repo, &fakeRegistries{items: []*registrydomain.Registry{agent, mcp, foreign}}, sig)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	row, err := svc.Set(ctx, SetAgentAccessRequest{GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalGroup, PrincipalID: " eng ", Mode: "Selected", RegistryIDs: []ids.RegistryID{agent.ID}})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if row.PrincipalID != "eng" || row.Mode != storeaccessdomain.AgentModeSelected || !slices.Equal(row.RegistryIDs, []ids.RegistryID{agent.ID}) || sig.n != 1 {
		t.Fatalf("saved %+v, signals %d", row, sig.n)
	}

	for name, in := range map[string]SetAgentAccessRequest{
		"an MCP registry":            {GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalAll, Mode: "selected", RegistryIDs: []ids.RegistryID{mcp.ID}},
		"another gateway's agent":    {GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalAll, Mode: "selected", RegistryIDs: []ids.RegistryID{foreign.ID}},
		"an unknown registry":        {GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalAll, Mode: "selected", RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()}},
		"an id on the all row":       {GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalAll, PrincipalID: "ana", Mode: "all"},
		"a user without an id":       {GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalUser, Mode: "none"},
		"an unknown mode":            {GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalAll, Mode: "open"},
		"an unknown principal type":  {GatewayID: gw, PrincipalType: "team", PrincipalID: "x", Mode: "all"},
		"a delete without principal": {GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalGroup},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Set(ctx, in); !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("expected a validation error, got %v", err)
			}
		})
	}
	if _, err := svc.Set(ctx, SetAgentAccessRequest{GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalAll, Mode: "selected", RegistryIDs: []ids.RegistryID{mcp.ID}}); !errors.Is(err, ErrUnknownAgent) {
		t.Fatalf("an MCP registry must be ErrUnknownAgent, got %v", err)
	}
	if sig.n != 1 {
		t.Fatalf("a refused write must not signal, got %d", sig.n)
	}

	deleted, err := svc.Set(ctx, SetAgentAccessRequest{GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalGroup, PrincipalID: "eng"})
	if err != nil || deleted != nil {
		t.Fatalf("delete: %+v %v", deleted, err)
	}
	if len(repo.rows) != 0 || len(repo.deleted) != 1 || sig.n != 2 {
		t.Fatalf("delete left %d rows, %d deletes, %d signals", len(repo.rows), len(repo.deleted), sig.n)
	}
}

func TestAgentAccessRegistryCleanerPrunes(t *testing.T) {
	repo := &fakeAgentAccessRepo{}
	reg := ids.New[ids.RegistryKind]()
	if err := NewAgentAccessRegistryCleaner(repo).DeleteByRegistry(context.Background(), ids.New[ids.GatewayKind](), reg); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(repo.pruned, []ids.RegistryID{reg}) {
		t.Fatalf("pruned %v", repo.pruned)
	}
}
