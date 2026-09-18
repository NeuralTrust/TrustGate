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
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	registrymocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func existingPolicy(t *testing.T) *domain.Policy {
	t.Helper()
	p, err := domain.NewPolicy(ids.New[ids.GatewayKind](), "old", "rate_limiter", true, 0, false, nil, nil, "old description", domain.ModeEnforce, nil)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

func ptr[T any](v T) *T { return &v }

func validUpdateInput(id ids.PolicyID) apppolicy.UpdateInput {
	return apppolicy.UpdateInput{
		ID:          id,
		Name:        ptr("new"),
		Description: ptr("new description"),
		Slug:        ptr("rate_limiter"),
		Enabled:     ptr(true),
	}
}

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.ID == existing.ID && p.Name == "new" && p.Description == "new description"
	}), false).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).
		Once()

	updater := apppolicy.NewUpdater(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.Update(context.Background(), validUpdateInput(existing.ID))
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "new" {
		t.Fatalf("Name = %q, want %q", got.Name, "new")
	}
	if got.Description != "new description" {
		t.Fatalf("Description = %q, want %q", got.Description, "new description")
	}
}

func TestUpdater_Update_Partial(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.Name == "renamed" && p.Slug == "rate_limiter" && p.Description == "old description"
	}), false).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).
		Once()

	updater := apppolicy.NewUpdater(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:   existing.ID,
		Name: ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "renamed" {
		t.Fatalf("Name = %q, want renamed", got.Name)
	}
	if got.Slug != "rate_limiter" {
		t.Fatalf("Slug = %q, want preserved rate_limiter", got.Slug)
	}
	if got.Description != "old description" {
		t.Fatalf("Description = %q, want preserved old description", got.Description)
	}
}

func TestUpdater_Update_PreservesModeWhenOmitted(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.Mode = domain.ModeObserve
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.Mode == domain.ModeObserve
	}), false).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).
		Once()

	updater := apppolicy.NewUpdater(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.Update(context.Background(), apppolicy.UpdateInput{ID: existing.ID, Name: ptr("renamed")})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Mode != domain.ModeObserve {
		t.Fatalf("Mode = %q, want preserved observe", got.Mode)
	}
}

func TestUpdater_Update_SetsModeWhenProvided(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.Mode == domain.ModeThrottle
	}), false).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).
		Once()

	updater := apppolicy.NewUpdater(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.Update(context.Background(), apppolicy.UpdateInput{ID: existing.ID, Mode: ptr(domain.ModeThrottle)})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Mode != domain.ModeThrottle {
		t.Fatalf("Mode = %q, want throttle", got.Mode)
	}
}

func TestUpdater_Update_RejectsGatewayIDChange(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)

	updater := apppolicy.NewUpdater(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
	in := validUpdateInput(existing.ID)
	in.GatewayID = ids.New[ids.GatewayKind]()
	_, err := updater.Update(context.Background(), in)
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.PolicyKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	publisher := cachemocks.NewEventPublisher(t)

	updater := apppolicy.NewUpdater(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), validUpdateInput(id))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

// Changing the slug of a scoped policy points its mcp_scope at another plugin.
// The associator only checks the protocol when a policy is attached, and
// nothing filters by protocol at request time, so the slug change is the last
// chance to refuse a scope on a plugin that does not serve MCP.
func TestUpdater_Update_SlugChangeRevalidatesTheStoredScope(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.MCPScope = &domain.MCPScope{RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()}}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := apppolicy.NewUpdater(
		repo, freeLevels(t), registrymocks.NewRepository(t),
		newScopedRegistryMock(t, appplugins.ProtocolLLM),
		newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil,
	)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:   existing.ID,
		Slug: ptr("semantic_cache"),
	})
	if !errors.Is(err, domain.ErrInvalidMCPScope) {
		t.Fatalf("err = %v, want ErrInvalidMCPScope", err)
	}
}

// The same change on a plugin that does serve MCP goes through, and it must not
// rewrite mcp_scope: the update never carried one.
func TestUpdater_Update_SlugChangeKeepsAScopeItDoesNotWrite(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.MCPScope = &domain.MCPScope{RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()}}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.Slug == "trustguard"
	}), false).Return(nil).Once()

	updater := newScopeUpdater(t, repo, registrymocks.NewRepository(t), expectInvalidation(t, existing.GatewayID))
	if _, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:   existing.ID,
		Slug: ptr("trustguard"),
	}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

// A slug change on a policy pruned to {} must still go through: the scope is
// empty because a registry was deleted, not because the operator sent one.
func TestUpdater_Update_SlugChangeOnPrunedScopeIsAllowed(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.MCPScope = &domain.MCPScope{}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything, false).Return(nil).Once()

	updater := newScopeUpdater(t, repo, registrymocks.NewRepository(t), expectInvalidation(t, existing.GatewayID))
	if _, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:   existing.ID,
		Slug: ptr("trustguard"),
	}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func newScopeUpdater(t *testing.T, repo *repomocks.Repository, registryRepo *registrymocks.Repository, publisher *cachemocks.EventPublisher) apppolicy.Updater {
	t.Helper()
	return apppolicy.NewUpdater(repo, freeLevels(t), registryRepo, newScopedRegistryMock(t, appplugins.ProtocolLLM, appplugins.ProtocolMCP), newCacheManager(), publisher, newTestLogger(), nil)
}

func expectInvalidation(t *testing.T, gwID ids.GatewayID) *cachemocks.EventPublisher {
	t.Helper()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()
	return publisher
}

// A policy pruned to {} by a registry delete must still be renameable: the
// "at least one entry" rule only applies when the scope arrives in the input.
func TestUpdater_Update_OmittedScopeKeepsPrunedScope(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.MCPScope = &domain.MCPScope{}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.Name == "renamed" && p.MCPScope != nil && p.MCPScope.IsEmpty()
	}), false).Return(nil).Once()

	updater := newScopeUpdater(t, repo, registrymocks.NewRepository(t), expectInvalidation(t, existing.GatewayID))
	got, err := updater.Update(context.Background(), apppolicy.UpdateInput{ID: existing.ID, Name: ptr("renamed")})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.MCPScope == nil || !got.MCPScope.IsEmpty() {
		t.Fatalf("MCPScope = %+v, want the pruned {} preserved", got.MCPScope)
	}
}

func TestUpdater_Update_OmittedScopeKeepsExistingScope(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	snowflake := ids.New[ids.RegistryKind]()
	existing.MCPScope = &domain.MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.MCPScope != nil && len(p.MCPScope.RegistryIDs) == 1 && p.MCPScope.RegistryIDs[0] == snowflake
	}), false).Return(nil).Once()

	updater := newScopeUpdater(t, repo, registrymocks.NewRepository(t), expectInvalidation(t, existing.GatewayID))
	if _, err := updater.Update(context.Background(), apppolicy.UpdateInput{ID: existing.ID, Name: ptr("renamed")}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func TestUpdater_Update_NullScopeClearsIt(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.MCPScope = &domain.MCPScope{RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()}}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.MCPScope == nil
	}), true).Return(nil).Once()

	updater := newScopeUpdater(t, repo, registrymocks.NewRepository(t), expectInvalidation(t, existing.GatewayID))
	got, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:       existing.ID,
		MCPScope: apppolicy.MCPScopePatch{Set: true, Value: nil},
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.MCPScope != nil {
		t.Fatalf("MCPScope = %+v, want nil after an explicit null", got.MCPScope)
	}
}

func TestUpdater_Update_ScopeValueReplacesAfterValidation(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	old := ids.New[ids.RegistryKind]()
	jira := ids.New[ids.RegistryKind]()
	existing.MCPScope = &domain.MCPScope{RegistryIDs: []ids.RegistryID{old}}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.MCPScope != nil && len(p.MCPScope.RegistryIDs) == 0 &&
			len(p.MCPScope.Tools) == 1 && p.MCPScope.Tools[0].RegistryID == jira && p.MCPScope.Tools[0].Tool == "create_issue" &&
			len(p.MCPScope.ExceptGroups) == 1 && p.MCPScope.ExceptGroups[0] == "Finanzas"
	}), true).Return(nil).Once()

	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, existing.GatewayID, sameRegistryIDs(jira)).
		Return([]*registrydomain.Registry{mcpRegistry(existing.GatewayID, jira)}, nil).
		Once()

	updater := newScopeUpdater(t, repo, registryRepo, expectInvalidation(t, existing.GatewayID))
	got, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID: existing.ID,
		MCPScope: apppolicy.MCPScopePatch{Set: true, Value: &domain.MCPScope{
			Tools:        []domain.MCPToolRef{{RegistryID: jira, Tool: " create_issue "}},
			ExceptGroups: []string{" Finanzas "},
		}},
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if len(got.MCPScope.RegistryIDs) != 0 {
		t.Fatalf("RegistryIDs = %v, want the old destination replaced", got.MCPScope.RegistryIDs)
	}
}

func TestUpdater_Update_RejectsEmptyScopeValue(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	publisher := cachemocks.NewEventPublisher(t)

	updater := newScopeUpdater(t, repo, registrymocks.NewRepository(t), publisher)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:       existing.ID,
		MCPScope: apppolicy.MCPScopePatch{Set: true, Value: &domain.MCPScope{}},
	})
	if !errors.Is(err, domain.ErrInvalidMCPScope) {
		t.Fatalf("err = %v, want ErrInvalidMCPScope", err)
	}
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_RejectsScopeWithForeignRegistry(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	foreign := ids.New[ids.RegistryKind]()
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().FindByIDs(mock.Anything, existing.GatewayID, sameRegistryIDs(foreign)).Return(nil, nil).Once()
	publisher := cachemocks.NewEventPublisher(t)

	updater := newScopeUpdater(t, repo, registryRepo, publisher)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:       existing.ID,
		MCPScope: apppolicy.MCPScopePatch{Set: true, Value: &domain.MCPScope{RegistryIDs: []ids.RegistryID{foreign}}},
	})
	if !errors.Is(err, domain.ErrInvalidMCPScope) {
		t.Fatalf("err = %v, want ErrInvalidMCPScope", err)
	}
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}
