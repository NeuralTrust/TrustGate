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

package registry_test

import (
	"context"
	"testing"
	"time"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func pinnedMCPRegistry(t *testing.T) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), "mcp", "", &domain.MCPTarget{URL: "https://mcp.example.com/mcp"})
	require.NoError(t, err)
	reg.ToolPolicy = domain.ToolPolicyPinned
	return reg
}

func storedTool(reg *domain.Registry, name, fp string, status domain.ToolStatus, decidedAt time.Time) domain.PinnedTool {
	return domain.PinnedTool{
		RegistryID: reg.ID, Name: name, Fingerprint: fp, Status: status,
		Definition: []byte(`{"name":"` + name + `"}`), DecidedAt: decidedAt,
	}
}

func TestPinnedToolService_List_AttachesTheApprovedDefinitionToAPendingOne(t *testing.T) {
	t.Parallel()
	reg := pinnedMCPRegistry(t)
	old, newer := time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
	regs := repomocks.NewRepository(t)
	regs.EXPECT().FindByID(mock.Anything, reg.ID).Return(reg, nil)
	tools := repomocks.NewPinnedToolRepository(t)
	tools.EXPECT().ListByRegistry(mock.Anything, reg.GatewayID, reg.ID).Return([]domain.PinnedTool{
		storedTool(reg, "search", "v1", domain.ToolStatusApproved, old),
		storedTool(reg, "search", "v2", domain.ToolStatusApproved, newer),
		storedTool(reg, "search", "v3", domain.ToolStatusPending, time.Time{}),
		storedTool(reg, "fresh", "f1", domain.ToolStatusPending, time.Time{}),
		storedTool(reg, "bad", "b1", domain.ToolStatusRejected, old),
	}, nil)
	svc := appregistry.NewPinnedToolService(regs, tools, newCacheManager(), nil, newTestLogger(), nil)

	got, err := svc.List(context.Background(), reg.GatewayID, reg.ID, nil)
	require.NoError(t, err)
	assert.Equal(t, domain.ToolPolicyPinned, got.ToolPolicy)
	require.Len(t, got.Items, 5)

	byFP := map[string]appregistry.PinnedToolView{}
	for _, it := range got.Items {
		byFP[it.Fingerprint] = it
	}
	require.NotNil(t, byFP["v3"].Approved, "a changed tool must carry the approved definition to diff against")
	assert.Equal(t, "v2", byFP["v3"].Approved.Fingerprint, "the most recently decided approval is the exposed one")
	assert.Nil(t, byFP["f1"].Approved, "a tool never approved has nothing to diff against")
	assert.Nil(t, byFP["v1"].Approved, "only pending rows carry it")
	assert.Nil(t, byFP["b1"].Approved)
}

func TestPinnedToolService_List_FiltersByStatus(t *testing.T) {
	t.Parallel()
	reg := pinnedMCPRegistry(t)
	regs := repomocks.NewRepository(t)
	regs.EXPECT().FindByID(mock.Anything, reg.ID).Return(reg, nil)
	tools := repomocks.NewPinnedToolRepository(t)
	tools.EXPECT().ListByRegistry(mock.Anything, reg.GatewayID, reg.ID).Return([]domain.PinnedTool{
		storedTool(reg, "a", "1", domain.ToolStatusApproved, time.Now()),
		storedTool(reg, "a", "2", domain.ToolStatusPending, time.Time{}),
	}, nil)
	svc := appregistry.NewPinnedToolService(regs, tools, newCacheManager(), nil, newTestLogger(), nil)

	pending := domain.ToolStatusPending
	got, err := svc.List(context.Background(), reg.GatewayID, reg.ID, &pending)
	require.NoError(t, err)
	require.Len(t, got.Items, 1)
	assert.Equal(t, "2", got.Items[0].Fingerprint)
	assert.NotNil(t, got.Items[0].Approved, "the diff base survives the status filter")
}

func TestPinnedToolService_List_RegistryOfAnotherGatewayIsNotFound(t *testing.T) {
	t.Parallel()
	reg := pinnedMCPRegistry(t)
	regs := repomocks.NewRepository(t)
	regs.EXPECT().FindByID(mock.Anything, reg.ID).Return(reg, nil)
	tools := repomocks.NewPinnedToolRepository(t) // must not be read
	svc := appregistry.NewPinnedToolService(regs, tools, newCacheManager(), nil, newTestLogger(), nil)

	_, err := svc.List(context.Background(), ids.New[ids.GatewayKind](), reg.ID, nil)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}
