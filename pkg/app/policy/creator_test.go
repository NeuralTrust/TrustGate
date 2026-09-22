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
	"io"
	"log/slog"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	registrymocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

// newRegistryMock returns a plugin registry mock whose ValidateStages yields
// stagesErr. It is marked Maybe() so tests where validation is never reached
// (e.g. domain validation fails first) do not fail on an unmet expectation.
// Get resolves nothing, matching a plugin that never opted into
// appplugins.CredentialSettings (see PluginCredentialPaths): the RUN-1646
// resolve/reject path is a no-op for every test using this helper unless it
// overrides Get itself.
func newRegistryMock(t *testing.T, stagesErr error) *pluginmocks.Registry {
	t.Helper()
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(stagesErr).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Get(mock.Anything).Return(nil, false).Maybe()
	return reg
}

// newRegistryRepo returns a registry repository mock with no expectations: a
// policy without mcp_scope must never look registries up, so any call fails
// the test.
func newRegistryRepo(t *testing.T) *registrymocks.Repository {
	t.Helper()
	return registrymocks.NewRepository(t)
}

// newScopedRegistryMock is like newRegistryMock, plus a Get that resolves
// every slug to a plugin declaring the given protocols, which
// validateMCPScope consults. It does not delegate to newRegistryMock: that
// helper's own Get stub (unscoped, "no credential paths") is registered
// first and, per testify's mock matching, a later stub for the same method
// signature never overrides an earlier one — so this builds its own
// registry with the scoped Get as the only registration for that method.
func newScopedRegistryMock(t *testing.T, protocols ...appplugins.Protocol) *pluginmocks.Registry {
	t.Helper()
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Maybe()
	plugin := pluginmocks.NewPlugin(t)
	plugin.EXPECT().SupportedProtocols().Return(protocols).Maybe()
	reg.EXPECT().Get(mock.Anything).Return(plugin, true).Maybe()
	return reg
}

func mcpRegistry(gwID ids.GatewayID, id ids.RegistryID) *registrydomain.Registry {
	return &registrydomain.Registry{ID: id, GatewayID: gwID, Type: registrydomain.TypeMCP, Enabled: true}
}

func llmRegistry(gwID ids.GatewayID, id ids.RegistryID) *registrydomain.Registry {
	return &registrydomain.Registry{ID: id, GatewayID: gwID, Type: registrydomain.TypeLLM, Enabled: true}
}

func sameRegistryIDs(want ...ids.RegistryID) interface{} {
	return mock.MatchedBy(func(got []ids.RegistryID) bool {
		if len(got) != len(want) {
			return false
		}
		seen := make(map[ids.RegistryID]struct{}, len(got))
		for _, id := range got {
			seen[id] = struct{}{}
		}
		for _, id := range want {
			if _, ok := seen[id]; !ok {
				return false
			}
		}
		return true
	})
}

func validCreateInput(gwID ids.GatewayID) apppolicy.CreateInput {
	return apppolicy.CreateInput{
		GatewayID: gwID,
		Name:      "default",
		Slug:      "rate_limiter",
		Enabled:   true,
		Settings:  map[string]any{"limit": 100},
	}
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
			return p.GatewayID == gwID && p.Name == "default" && p.Slug == "rate_limiter" && !p.Global
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := apppolicy.NewCreator(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), mgr, newTestLogger(), nil)

	p, err := creator.Create(context.Background(), validCreateInput(gwID))
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	cached, ok := mgr.GetTTLMap(cache.PolicyTTLName).Get(p.ID.String())
	if !ok {
		t.Fatal("created policy was not pre-warmed in the cache")
	}
	if cached.(*domain.Policy).ID != p.ID {
		t.Fatal("cached policy ID mismatch")
	}
}

func TestCreator_Create_RejectsInvalid(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	creator := apppolicy.NewCreator(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), newTestLogger(), nil)

	in := validCreateInput(ids.New[ids.GatewayKind]())
	in.Name = ""
	_, err := creator.Create(context.Background(), in)
	if !errors.Is(err, domain.ErrInvalidName) {
		t.Fatalf("err = %v, want ErrInvalidName", err)
	}
}

func TestCreator_Create_RejectsUnsupportedStage(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	sentinel := errors.New("stage not supported")
	creator := apppolicy.NewCreator(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, sentinel), newCacheManager(), newTestLogger(), nil)

	_, err := creator.Create(context.Background(), validCreateInput(ids.New[ids.GatewayKind]()))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want registry stage error", err)
	}
}

func TestCreator_Create_RejectsUnsupportedMode(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	sentinel := errors.New("mode not supported")
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(sentinel).Once()
	reg.EXPECT().Get(mock.Anything).Return(nil, false).Maybe()
	creator := apppolicy.NewCreator(repo, freeLevels(t), newRegistryRepo(t), reg, newCacheManager(), newTestLogger(), nil)

	_, err := creator.Create(context.Background(), validCreateInput(ids.New[ids.GatewayKind]()))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want registry mode error", err)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrAlreadyExists).Once()
	creator := apppolicy.NewCreator(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), newTestLogger(), nil)

	in := validCreateInput(ids.New[ids.GatewayKind]())
	in.Name = "dupe"
	_, err := creator.Create(context.Background(), in)
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestCreator_Create_DefaultsToNonGlobal(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	creator := apppolicy.NewCreator(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), newTestLogger(), nil)

	p, err := creator.Create(context.Background(), validCreateInput(ids.New[ids.GatewayKind]()))
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if p.Global {
		t.Fatal("a freshly-created policy must not be global")
	}
}

func TestCreator_Create_WithMCPScope_StoresNormalizedScope(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	snowflake := ids.New[ids.RegistryKind]()
	jira := ids.New[ids.RegistryKind]()

	registryRepo := newRegistryRepo(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, sameRegistryIDs(snowflake, jira)).
		Return([]*registrydomain.Registry{mcpRegistry(gwID, snowflake), mcpRegistry(gwID, jira)}, nil).
		Once()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
			return p.MCPScope != nil &&
				len(p.MCPScope.RegistryIDs) == 1 && p.MCPScope.RegistryIDs[0] == snowflake &&
				len(p.MCPScope.Tools) == 1 && p.MCPScope.Tools[0].Tool == "run_query" &&
				len(p.MCPScope.Groups) == 1 && p.MCPScope.Groups[0] == "Finanzas"
		})).
		Return(nil).
		Once()

	creator := apppolicy.NewCreator(repo, freeLevels(t), registryRepo, newScopedRegistryMock(t, appplugins.ProtocolLLM, appplugins.ProtocolMCP), newCacheManager(), newTestLogger(), nil)
	in := validCreateInput(gwID)
	in.MCPScope = &domain.MCPScope{
		RegistryIDs: []ids.RegistryID{snowflake},
		Tools:       []domain.MCPToolRef{{RegistryID: jira, Tool: "  run_query "}},
		Groups:      []string{" Finanzas "},
	}
	p, err := creator.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if p.MCPScope == nil || p.MCPScope.Tools[0].Tool != "run_query" || p.MCPScope.Groups[0] != "Finanzas" {
		t.Fatalf("scope was not normalised before saving: %+v", p.MCPScope)
	}
}

func TestCreator_Create_PrincipalOnlyScope_SkipsRegistryLookup(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.MCPScope != nil && len(p.MCPScope.Groups) == 1 && p.MCPScope.Groups[0] == "Finanzas"
	})).Return(nil).Once()

	creator := apppolicy.NewCreator(repo, freeLevels(t), newRegistryRepo(t), newScopedRegistryMock(t, appplugins.ProtocolMCP), newCacheManager(), newTestLogger(), nil)
	in := validCreateInput(ids.New[ids.GatewayKind]())
	in.MCPScope = &domain.MCPScope{Groups: []string{" Finanzas "}}
	if _, err := creator.Create(context.Background(), in); err != nil {
		t.Fatalf("Create error: %v", err)
	}
}
