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
	"errors"
	"log/slog"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// plainRepo is the registry repository as a full-mode pod has it: it knows
// nothing about pinned tools, so PinnedTools always comes back empty.
type plainRepo struct {
	domain.Repository
	regs []*domain.Registry
}

func (r plainRepo) FindByID(context.Context, ids.RegistryID) (*domain.Registry, error) {
	return r.regs[0], nil
}

func (r plainRepo) FindByIDs(context.Context, ids.GatewayID, []ids.RegistryID) ([]*domain.Registry, error) {
	return r.regs, nil
}

func (r plainRepo) List(context.Context, domain.ListFilter) ([]*domain.Registry, int, error) {
	return r.regs, len(r.regs), nil
}

type fakeLister struct {
	tools map[ids.RegistryID][]domain.PinnedTool
	errs  map[ids.RegistryID]error
	reads []ids.RegistryID
}

func (f *fakeLister) ListByRegistry(_ context.Context, _ ids.GatewayID, id ids.RegistryID) ([]domain.PinnedTool, error) {
	f.reads = append(f.reads, id)
	return f.tools[id], f.errs[id]
}

func mcpReg(t *testing.T, policy domain.ToolPolicy) *domain.Registry {
	t.Helper()
	id, err := ids.NewV7[ids.RegistryKind]()
	require.NoError(t, err)
	return &domain.Registry{ID: id, GatewayID: ids.New[ids.GatewayKind](), Type: domain.TypeMCP, ToolPolicy: policy}
}

func TestPinnedReaderStampsPinnedRegistriesOnEveryRead(t *testing.T) {
	t.Parallel()
	pinned := mcpReg(t, domain.ToolPolicyPinned)
	auto := mcpReg(t, domain.ToolPolicyAuto)
	lister := &fakeLister{tools: map[ids.RegistryID][]domain.PinnedTool{
		pinned.ID: {{Name: "a", Fingerprint: "fa", Status: domain.ToolStatusApproved}},
	}}
	repo := appregistry.WithPinnedTools(plainRepo{regs: []*domain.Registry{pinned, auto}}, lister, slog.New(slog.DiscardHandler))
	want := []domain.ToolDecision{{Name: "a", Fingerprint: "fa", Status: domain.ToolStatusApproved}}

	byIDs, err := repo.FindByIDs(context.Background(), pinned.GatewayID, nil)
	require.NoError(t, err)
	assert.Equal(t, want, byIDs[0].PinnedTools)
	assert.Empty(t, byIDs[1].PinnedTools)
	assert.Equal(t, []ids.RegistryID{pinned.ID}, lister.reads, "auto registries are never read")

	pinned.PinnedTools = nil
	one, err := repo.FindByID(context.Background(), pinned.ID)
	require.NoError(t, err)
	assert.Equal(t, want, one.PinnedTools)

	pinned.PinnedTools = nil
	listed, _, err := repo.List(context.Background(), domain.ListFilter{})
	require.NoError(t, err)
	assert.Equal(t, want, listed[0].PinnedTools)
}

func TestPinnedReaderReadErrorExposesNothingAndDoesNotFailTheLoad(t *testing.T) {
	t.Parallel()
	broken := mcpReg(t, domain.ToolPolicyPinned)
	broken.PinnedTools = []domain.ToolDecision{{Name: "stale", Fingerprint: "f", Status: domain.ToolStatusApproved}}
	healthy := mcpReg(t, domain.ToolPolicyPinned)
	lister := &fakeLister{
		tools: map[ids.RegistryID][]domain.PinnedTool{healthy.ID: {{Name: "a", Fingerprint: "fa", Status: domain.ToolStatusApproved}}},
		errs:  map[ids.RegistryID]error{broken.ID: errors.New("db down")},
	}
	repo := appregistry.WithPinnedTools(plainRepo{regs: []*domain.Registry{broken, healthy}}, lister, nil)

	got, err := repo.FindByIDs(context.Background(), broken.GatewayID, nil)
	require.NoError(t, err, "one unreadable registry must not fail the whole gateway load")
	assert.Empty(t, got[0].PinnedTools, "fail closed: no approved tools")
	assert.False(t, got[0].IsToolApproved(domain.ToolRef{Name: "stale", Fingerprint: "f"}))
	assert.Len(t, got[1].PinnedTools, 1, "the other registry keeps its set")
}
