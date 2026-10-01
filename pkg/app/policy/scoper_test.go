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

package policy_test

import (
	"context"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type scoperCall func(s apppolicy.Scoper, ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error)

type placement int

const (
	placedDraft placement = iota
	placedGlobal
	placedMCPWide
)

// flagWrite is the repository write a transition is expected to make. A
// promotion passes the updated_at it read, so the write lands only on that
// row; a demotion passes the zero time and lands on whatever is there. When it
// succeeds, the mock answers with the case's wanted flags and a new
// updated_at, so the case pins that the scoper answers with the row as written.
type flagWrite struct {
	mcpWide     bool
	on          bool
	conditional bool
	err         error
}

func TestScoper_Placement(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		from placement
		call scoperCall
		// protocols is what the policy's plugin supports. nil means the plugin
		// registry must not be consulted at all.
		protocols   []appplugins.Protocol
		foreign     bool
		write       *flagWrite
		wantErr     []error
		wantGlobal  bool
		wantMCPWide bool
	}{
		{
			name:        "SetMCPWide promotes a draft",
			from:        placedDraft,
			call:        apppolicy.Scoper.SetMCPWide,
			protocols:   []appplugins.Protocol{appplugins.ProtocolLLM, appplugins.ProtocolMCP},
			write:       &flagWrite{mcpWide: true, on: true, conditional: true},
			wantMCPWide: true,
		},
		{
			name:        "SetMCPWide swaps a global policy and clears global",
			from:        placedGlobal,
			call:        apppolicy.Scoper.SetMCPWide,
			protocols:   []appplugins.Protocol{appplugins.ProtocolMCP},
			write:       &flagWrite{mcpWide: true, on: true, conditional: true},
			wantMCPWide: true,
		},
		{
			name:        "SetMCPWide on an MCP-wide policy is a no-op",
			from:        placedMCPWide,
			call:        apppolicy.Scoper.SetMCPWide,
			wantMCPWide: true,
		},
		{
			name:    "SetMCPWide on another gateway's policy is not found",
			from:    placedDraft,
			call:    apppolicy.Scoper.SetMCPWide,
			foreign: true,
			wantErr: []error{domain.ErrNotFound},
		},
		{
			name:      "SetMCPWide refuses a plugin that does not run on MCP",
			from:      placedDraft,
			call:      apppolicy.Scoper.SetMCPWide,
			protocols: []appplugins.Protocol{appplugins.ProtocolLLM},
			wantErr:   []error{domain.ErrMCPWideUnsupported, commonerrors.ErrValidation},
		},
		{
			name:      "SetMCPWide on a row updated since the read is a conflict",
			from:      placedDraft,
			call:      apppolicy.Scoper.SetMCPWide,
			protocols: []appplugins.Protocol{appplugins.ProtocolMCP},
			write:     &flagWrite{mcpWide: true, on: true, conditional: true, err: domain.ErrPlacementChanged},
			wantErr:   []error{domain.ErrPlacementChanged, commonerrors.ErrConflict},
		},
		{
			name:  "UnsetMCPWide demotes unconditionally",
			from:  placedMCPWide,
			call:  apppolicy.Scoper.UnsetMCPWide,
			write: &flagWrite{mcpWide: true, on: false},
		},
		{
			name: "UnsetMCPWide on a draft is a no-op",
			from: placedDraft,
			call: apppolicy.Scoper.UnsetMCPWide,
		},
		{
			name:        "UnsetGlobal on an MCP-wide policy is a no-op",
			from:        placedMCPWide,
			call:        apppolicy.Scoper.UnsetGlobal,
			wantMCPWide: true,
		},
		{
			name:       "SetGlobal promotes a draft",
			from:       placedDraft,
			call:       apppolicy.Scoper.SetGlobal,
			write:      &flagWrite{on: true, conditional: true},
			wantGlobal: true,
		},
		{
			name:       "SetGlobal swaps an MCP-wide policy and clears mcp_wide",
			from:       placedMCPWide,
			call:       apppolicy.Scoper.SetGlobal,
			write:      &flagWrite{on: true, conditional: true},
			wantGlobal: true,
		},
		{
			name:       "SetGlobal on a global policy is a no-op",
			from:       placedGlobal,
			call:       apppolicy.Scoper.SetGlobal,
			wantGlobal: true,
		},
		{
			name:    "SetGlobal on another gateway's policy is not found",
			from:    placedDraft,
			call:    apppolicy.Scoper.SetGlobal,
			foreign: true,
			wantErr: []error{domain.ErrNotFound},
		},
		{
			name:    "SetGlobal on a row updated since the read is a conflict",
			from:    placedDraft,
			call:    apppolicy.Scoper.SetGlobal,
			write:   &flagWrite{on: true, conditional: true, err: domain.ErrPlacementChanged},
			wantErr: []error{domain.ErrPlacementChanged},
		},
		{
			name:  "UnsetGlobal demotes unconditionally",
			from:  placedGlobal,
			call:  apppolicy.Scoper.UnsetGlobal,
			write: &flagWrite{on: false},
		},
		{
			name:        "UnsetGlobal answers the row as written when it was swapped to MCP-wide meanwhile",
			from:        placedGlobal,
			call:        apppolicy.Scoper.UnsetGlobal,
			write:       &flagWrite{on: false},
			wantMCPWide: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			existing := existingPolicy(t)
			switch tt.from {
			case placedGlobal:
				existing.Global = true
			case placedMCPWide:
				existing.MCPWide = true
			}
			readAt := existing.UpdatedAt
			writtenAt := readAt.Add(time.Second)
			gatewayID := existing.GatewayID
			if tt.foreign {
				gatewayID = ids.New[ids.GatewayKind]()
			}

			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
			publisher := cachemocks.NewEventPublisher(t)
			if tt.write != nil {
				written := domain.Placement{Global: tt.wantGlobal, MCPWide: tt.wantMCPWide, UpdatedAt: writtenAt}
				expectFlagWrite(repo, existing, *tt.write, readAt, written)
				if tt.write.err == nil {
					publisher.EXPECT().
						Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
						Return(nil).
						Once()
				}
			}
			var plugins *pluginmocks.Registry
			if tt.protocols != nil {
				plugins = newScopedRegistryMock(t, tt.protocols...)
			} else {
				plugins = pluginmocks.NewRegistry(t)
			}
			manager := newCacheManager()

			scoper := apppolicy.NewScoper(repo, freeLevels(t), plugins, manager, publisher, newTestLogger(), nil)
			got, err := tt.call(scoper, context.Background(), gatewayID, existing.ID)

			cached, isCached := manager.GetTTLMap(cache.PolicyTTLName).Get(existing.ID.String())
			if len(tt.wantErr) > 0 {
				for _, want := range tt.wantErr {
					require.ErrorIs(t, err, want)
				}
				assert.False(t, isCached, "a refused write must not reach the cache")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantGlobal, got.Global, "global")
			assert.Equal(t, tt.wantMCPWide, got.MCPWide, "mcp_wide")
			if tt.write == nil {
				assert.Equal(t, readAt, got.UpdatedAt, "a no-op answers the policy as read")
				assert.False(t, isCached, "a no-op must not touch the cache")
				return
			}
			assert.Equal(t, writtenAt, got.UpdatedAt, "updated_at is the one the write stored")
			require.True(t, isCached, "the written placement must be cached")
			assert.Same(t, got, cached, "the cache holds the copy the caller gets back")
		})
	}
}

func expectFlagWrite(repo *repomocks.Repository, p *domain.Policy, w flagWrite, readAt time.Time, written domain.Placement) {
	var expectedReadAt time.Time
	if w.conditional {
		expectedReadAt = readAt
	}
	if w.err != nil {
		written = domain.Placement{}
	}
	if w.mcpWide {
		repo.EXPECT().SetMCPWide(mock.Anything, p.GatewayID, p.ID, w.on, expectedReadAt).Return(written, w.err).Once()
		return
	}
	repo.EXPECT().SetGlobal(mock.Anything, p.GatewayID, p.ID, w.on, expectedReadAt).Return(written, w.err).Once()
}
