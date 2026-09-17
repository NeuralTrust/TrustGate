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
	"errors"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	registrymocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/stretchr/testify/mock"
)

func TestCreator_Create_RejectsInvalidMCPScope(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	snowflake := ids.New[ids.RegistryKind]()
	foreign := ids.New[ids.RegistryKind]()

	tests := []struct {
		name        string
		scope       *domain.MCPScope
		protocols   []appplugins.Protocol
		found       []*registrydomain.Registry
		wantMention string
	}{
		{
			name:        "empty scope",
			scope:       &domain.MCPScope{},
			protocols:   []appplugins.Protocol{appplugins.ProtocolMCP},
			wantMention: "no entries",
		},
		{
			name:        "registry from another gateway",
			scope:       &domain.MCPScope{RegistryIDs: []ids.RegistryID{foreign}},
			protocols:   []appplugins.Protocol{appplugins.ProtocolMCP},
			found:       nil,
			wantMention: foreign.String(),
		},
		{
			name:        "llm registry",
			scope:       &domain.MCPScope{Tools: []domain.MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}},
			protocols:   []appplugins.Protocol{appplugins.ProtocolMCP},
			found:       []*registrydomain.Registry{llmRegistry(gwID, snowflake)},
			wantMention: snowflake.String(),
		},
		{
			name:        "plugin without mcp protocol",
			scope:       &domain.MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
			protocols:   []appplugins.Protocol{appplugins.ProtocolLLM},
			wantMention: "rate_limiter",
		},
		{
			name:        "registry in both registry_ids and tools",
			scope:       &domain.MCPScope{RegistryIDs: []ids.RegistryID{snowflake}, Tools: []domain.MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}},
			protocols:   []appplugins.Protocol{appplugins.ProtocolMCP},
			wantMention: "both",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			registryRepo := registrymocks.NewRepository(t)
			if tt.found != nil || tt.name == "registry from another gateway" {
				registryRepo.EXPECT().FindByIDs(mock.Anything, gwID, mock.Anything).Return(tt.found, nil).Once()
			}
			repo := repomocks.NewRepository(t)
			creator := apppolicy.NewCreator(repo, registryRepo, newScopedRegistryMock(t, tt.protocols...), newCacheManager(), newTestLogger(), nil)

			in := validCreateInput(gwID)
			in.MCPScope = tt.scope
			_, err := creator.Create(context.Background(), in)
			if !errors.Is(err, domain.ErrInvalidMCPScope) {
				t.Fatalf("err = %v, want ErrInvalidMCPScope", err)
			}
			if !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("err = %v, want it to wrap ErrValidation", err)
			}
			if !strings.Contains(err.Error(), tt.wantMention) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantMention)
			}
			repo.AssertNotCalled(t, "Save", mock.Anything, mock.Anything)
		})
	}
}

func TestCreator_Create_MCPScope_PropagatesRegistryRepoError(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	snowflake := ids.New[ids.RegistryKind]()
	sentinel := errors.New("db down")

	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().FindByIDs(mock.Anything, gwID, mock.Anything).Return(nil, sentinel).Once()
	repo := repomocks.NewRepository(t)
	creator := apppolicy.NewCreator(repo, registryRepo, newScopedRegistryMock(t, appplugins.ProtocolMCP), newCacheManager(), newTestLogger(), nil)

	in := validCreateInput(gwID)
	in.MCPScope = &domain.MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}
	_, err := creator.Create(context.Background(), in)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the repository error", err)
	}
	if errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, an infrastructure failure must not read as a validation error", err)
	}
}

func TestCreator_Create_MCPScope_UnknownPluginIsLeftToPluginValidation(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	snowflake := ids.New[ids.RegistryKind]()

	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.Anything).
		Return([]*registrydomain.Registry{mcpRegistry(gwID, snowflake)}, nil).
		Once()
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Get(mock.Anything).Return(nil, false).Once()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()

	creator := apppolicy.NewCreator(repo, registryRepo, reg, newCacheManager(), newTestLogger(), nil)
	in := validCreateInput(gwID)
	in.MCPScope = &domain.MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}
	if _, err := creator.Create(context.Background(), in); err != nil {
		t.Fatalf("Create error: %v", err)
	}
}
