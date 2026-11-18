//go:build functional

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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
)

func TestAgentAccessRepositoryRoundTrip(t *testing.T) {
	ctx, pool := openEveryoneSchema(t)
	const ddl = `
		CREATE TABLE store_agent_access (
			gateway_id     UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
			principal_type TEXT NOT NULL,
			principal_id   TEXT NOT NULL,
			mode           TEXT NOT NULL,
			registry_ids   JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_at     TIMESTAMPTZ NOT NULL,
			updated_at     TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (gateway_id, principal_type, principal_id)
		);`
	if _, err := pool.Exec(ctx, ddl); err != nil {
		t.Fatalf("create table: %v", err)
	}
	repo := NewAgentAccessRepository(&database.Connection{Pool: pool}, nil)
	gw := insertGateway(t, ctx, pool)
	other := insertGateway(t, ctx, pool)
	a, b := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()

	rows := []*domain.AgentAccess{
		mustAgentAccess(t, gw, domain.PrincipalAll, "", "all", nil),
		mustAgentAccess(t, gw, domain.PrincipalGroup, "eng", "selected", []ids.RegistryID{a, b}),
		mustAgentAccess(t, gw, domain.PrincipalUser, "ana", "none", nil),
		mustAgentAccess(t, other, domain.PrincipalGroup, "eng", "selected", []ids.RegistryID{a}),
	}
	for _, row := range rows {
		if err := repo.UpsertAgentAccess(ctx, row); err != nil {
			t.Fatalf("UpsertAgentAccess: %v", err)
		}
	}
	got, err := repo.ListAgentAccessByGateway(ctx, gw)
	if err != nil || len(got) != 3 {
		t.Fatalf("ListAgentAccessByGateway: %d rows, %v", len(got), err)
	}
	if got[0].PrincipalType != domain.PrincipalAll || got[0].RegistryIDs != nil ||
		got[1].PrincipalID != "eng" || len(got[1].RegistryIDs) != 2 {
		t.Fatalf("round trip lost data: %+v %+v", got[0], got[1])
	}

	if err := repo.PruneAgentRegistry(ctx, gw, a); err != nil {
		t.Fatalf("PruneAgentRegistry: %v", err)
	}
	got, _ = repo.ListAgentAccessByGateway(ctx, gw)
	if len(got[1].RegistryIDs) != 1 || got[1].RegistryIDs[0] != b {
		t.Fatalf("prune must drop only the deleted registry, got %v", got[1].RegistryIDs)
	}
	if kept, _ := repo.ListAgentAccessByGateway(ctx, other); len(kept[0].RegistryIDs) != 1 {
		t.Fatalf("prune must leave other gateways alone, got %v", kept[0].RegistryIDs)
	}

	page, total, err := repo.ListAgentAccess(ctx, 1, 2)
	if err != nil || total != 4 || len(page) != 2 {
		t.Fatalf("paging: %d items, total %d, err %v", len(page), total, err)
	}

	if err := repo.DeleteAgentAccess(ctx, gw, domain.PrincipalUser, "ana"); err != nil {
		t.Fatalf("DeleteAgentAccess: %v", err)
	}
	if err := repo.DeleteAgentAccess(ctx, gw, domain.PrincipalUser, "ana"); err != nil {
		t.Fatalf("deleting a missing row must not fail: %v", err)
	}
	if got, _ := repo.ListAgentAccessByGateway(ctx, gw); len(got) != 2 {
		t.Fatalf("delete left %d rows", len(got))
	}

	unknown := mustAgentAccess(t, ids.New[ids.GatewayKind](), domain.PrincipalAll, "", "all", nil)
	if err := repo.UpsertAgentAccess(ctx, unknown); !errors.Is(err, domain.ErrInvalidAgentAccess) {
		t.Fatalf("an unknown gateway must be a validation error, got %v", err)
	}
}

func mustAgentAccess(t *testing.T, gw ids.GatewayID, pt domain.PrincipalType, id, mode string, regs []ids.RegistryID) *domain.AgentAccess {
	t.Helper()
	row, err := domain.NewAgentAccess(gw, pt, id, mode, regs)
	if err != nil {
		t.Fatalf("NewAgentAccess: %v", err)
	}
	return row
}
