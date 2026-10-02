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
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	consumermocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
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

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
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

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
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

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
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

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.Update(context.Background(), apppolicy.UpdateInput{ID: existing.ID, Mode: ptr(domain.ModeThrottle)})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Mode != domain.ModeThrottle {
		t.Fatalf("Mode = %q, want throttle", got.Mode)
	}
}

// TestUpdater_Update_RejectsInertSettingsWriteWhenSettingsCarried covers the
// RUN-1701 rule: an update that carries Settings must be treated the same as
// a create for the write-time-only rule, so a plugin's SettingsWriteValidator
// error (e.g. openai_moderation's explicit block_on_flagged: false with no
// thresholds) must block the update.
func TestUpdater_Update_RejectsInertSettingsWriteWhenSettingsCarried(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	sentinel := errors.New("policy could never block or report a violation")
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateSettingsWrite(mock.Anything, mock.Anything, mock.Anything).Return(sentinel).Once()

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), reg, newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:       existing.ID,
		Settings: &map[string]any{"limit": 100},
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the plugin's sentinel error", err)
	}
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want it to wrap ErrValidation", err)
	}
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// TestUpdater_Update_SettingsWriteForwardsThePriorSettings proves the normal
// (no slug change) case forwards the actual settings stored before this
// write, not nil - the write-time rule needs the real prior shape to decide
// which keys are pre-existing.
func TestUpdater_Update_SettingsWriteForwardsThePriorSettings(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.Settings = map[string]any{"limit": 50}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything, false).Return(nil).Once()

	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().
		ValidateSettingsWrite(mock.Anything, mock.Anything, mock.MatchedBy(func(prev map[string]any) bool {
			return prev != nil && prev["limit"] == 50
		})).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).
		Once()

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), reg, newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:       existing.ID,
		Settings: &map[string]any{"limit": 100},
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

// TestUpdater_Update_DisableOnlyDoesNotTriggerSettingsWriteValidation is the
// other half of the RUN-1701 constraint: an update that only disables (or
// renames) an existing, already-inert policy must still succeed, because it
// never carries settings. The registry mock below deliberately has no
// ValidateSettingsWrite expectation configured, so an unexpected call fails
// the test immediately (mock.Mock.Test(t) turns it into t.FailNow(), not a
// silent pass) - proving the updater does not call it for this input.
func TestUpdater_Update_DisableOnlyDoesNotTriggerSettingsWriteValidation(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return !p.Enabled
	}), false).Return(nil).Once()

	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Maybe()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).
		Once()

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), reg, newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:      existing.ID,
		Enabled: ptr(false),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

// A slug change re-targets the stored settings at another plugin, so it is a
// settings write even though the update carries no Settings.
func TestUpdater_Update_SlugChangeTriggersSettingsWriteValidation(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	sentinel := errors.New("policy could never block or report a violation")
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateSettingsWrite("openai_moderation", mock.Anything, mock.Anything).Return(sentinel).Once()

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), reg, newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:   existing.ID,
		Slug: ptr("openai_moderation"),
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the plugin's sentinel error", err)
	}
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// TestUpdater_Update_SlugChangeTreatsPreviousSettingsAsNil covers the other
// half of the slug-change rule: even though the policy already had settings
// stored (for its OLD plugin), a slug change must forward previous=nil to
// ValidateSettingsWrite. Those settings belong to a plugin the policy is no
// longer pointing at, so a key of theirs must never be read as "pre-existing"
// for the new plugin's write-time rule.
func TestUpdater_Update_SlugChangeTreatsPreviousSettingsAsNil(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.Settings = map[string]any{"limit": 100}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything, false).Return(nil).Once()

	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().
		ValidateSettingsWrite("openai_moderation", mock.Anything, mock.MatchedBy(func(prev map[string]any) bool {
			return prev == nil
		})).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).
		Once()

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), reg, newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:   existing.ID,
		Slug: ptr("openai_moderation"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

// Echoing the current slug back, as a full-form save does, is not a change.
func TestUpdater_Update_UnchangedSlugDoesNotTriggerSettingsWriteValidation(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything, false).Return(nil).Once()

	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Maybe()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).
		Once()

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), reg, newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:   existing.ID,
		Slug: ptr(existing.Slug),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func TestUpdater_Update_RejectsGatewayIDChange(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
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

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
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
		repo, nil, freeLevels(t), registrymocks.NewRepository(t),
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
	return apppolicy.NewUpdater(repo, nil, freeLevels(t), registryRepo, newScopedRegistryMock(t, appplugins.ProtocolLLM, appplugins.ProtocolMCP), newCacheManager(), publisher, newTestLogger(), nil)
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

// Attaching a destination-scoped policy to an LLM consumer is refused: the
// scope names a registry, and none exists outside MCP. Attaching it unscoped
// and then setting the scope used to reach the same end state, because the
// rule lived in the attach alone. Now the update applies it to the consumers
// the policy already holds.
func TestUpdater_Update_RefusesAScopeThatDoesNotReachAnAttachedConsumer(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	consumerID := ids.New[ids.ConsumerKind]()
	existing.ConsumerIDs = []ids.ConsumerID{consumerID}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	jira := ids.New[ids.RegistryKind]()
	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, existing.GatewayID, sameRegistryIDs(jira)).
		Return([]*registrydomain.Registry{mcpRegistry(existing.GatewayID, jira)}, nil).
		Once()

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().
		FindByID(mock.Anything, consumerID).
		Return(&consumerdomain.Consumer{ID: consumerID, Type: consumerdomain.TypeLLM}, nil).
		Once()

	updater := apppolicy.NewUpdater(
		repo, consumers, freeLevels(t), registryRepo,
		newScopedRegistryMock(t, appplugins.ProtocolLLM, appplugins.ProtocolMCP),
		newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil,
	)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:       existing.ID,
		MCPScope: apppolicy.MCPScopePatch{Set: true, Value: &domain.MCPScope{RegistryIDs: []ids.RegistryID{jira}}},
	})
	if !errors.Is(err, consumerdomain.ErrPolicyScopeDoesNotCross) {
		t.Fatalf("err = %v, want ErrPolicyScopeDoesNotCross", err)
	}
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// The same scope on an MCP consumer is exactly what the field is for.
func TestUpdater_Update_KeepsAScopeThatReachesItsConsumer(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	consumerID := ids.New[ids.ConsumerKind]()
	existing.ConsumerIDs = []ids.ConsumerID{consumerID}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything, true).Return(nil).Once()

	jira := ids.New[ids.RegistryKind]()
	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, existing.GatewayID, sameRegistryIDs(jira)).
		Return([]*registrydomain.Registry{mcpRegistry(existing.GatewayID, jira)}, nil).
		Once()

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().
		FindByID(mock.Anything, consumerID).
		Return(&consumerdomain.Consumer{ID: consumerID, Type: consumerdomain.TypeMCP}, nil).
		Once()

	updater := apppolicy.NewUpdater(
		repo, consumers, freeLevels(t), registryRepo,
		newScopedRegistryMock(t, appplugins.ProtocolLLM, appplugins.ProtocolMCP),
		newCacheManager(), expectInvalidation(t, existing.GatewayID), newTestLogger(), nil,
	)
	if _, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:       existing.ID,
		MCPScope: apppolicy.MCPScopePatch{Set: true, Value: &domain.MCPScope{RegistryIDs: []ids.RegistryID{jira}}},
	}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

// consoleWriteBody is the full write body the console sends on every save,
// pause included: every field present, settings resent (normalised, so not
// necessarily byte-equal to the stored ones).
func consoleWriteBody(existing *domain.Policy, enabled bool) apppolicy.UpdateInput {
	settings := map[string]any{"limit": -1}
	stages := []domain.Stage{domain.StagePreRequest}
	return apppolicy.UpdateInput{
		ID:          existing.ID,
		Name:        ptr(existing.Name),
		Description: ptr(existing.Description),
		Slug:        ptr(existing.Slug),
		Enabled:     ptr(enabled),
		Priority:    ptr(existing.Priority),
		Parallel:    ptr(existing.Parallel),
		Settings:    &settings,
		Stages:      &stages,
		Mode:        ptr(existing.Mode),
	}
}

// brokenRegistry rejects everything: an unknown slug, or settings tightened
// after the row was stored.
func brokenRegistry(t *testing.T) *pluginmocks.Registry {
	t.Helper()
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(appplugins.ErrUnknownPlugin).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(appplugins.ErrUnknownPlugin).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(appplugins.ErrUnknownPlugin).Maybe()
	reg.EXPECT().ValidateSettingsWrite(mock.Anything, mock.Anything, mock.Anything).Return(errors.New("write rule")).Maybe()
	return reg
}

// Pausing is the console's remedy for an "error" policy. The console resends
// the whole body, so the rule keys on the resulting state, not on the shape.
func TestUpdater_Update_PausingAnUnloadablePolicyWithTheFullConsoleBodySucceeds(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return !p.Enabled
	}), false).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).Once()

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), brokenRegistry(t), newCacheManager(), publisher, newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), consoleWriteBody(existing, false)); err != nil {
		t.Fatalf("pausing an unloadable policy failed: %v", err)
	}
}

// Re-enabling the same row with the same body goes through validation again.
func TestUpdater_Update_ReEnablingAnUnloadablePolicyIsValidated(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.Enabled = false
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), brokenRegistry(t), newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), consoleWriteBody(existing, true)); err == nil {
		t.Fatal("expected validation error on re-enable")
	}
}

// Enabling a valid policy still passes through the validators.
func TestUpdater_Update_EnablingAValidPolicyStillValidates(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.Enabled = false
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything, false).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).Once()

	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(nil).Once()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(nil).Once()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Once()
	reg.EXPECT().ValidateSettingsWrite(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), reg, newCacheManager(), publisher, newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), consoleWriteBody(existing, true)); err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

// Only the enabled -> disabled transition skips the plugin checks. Editing a
// policy that is already paused validates exactly as it always has, so junk
// cannot be saved into a paused row.
func TestUpdater_Update_EditingAnAlreadyPausedPolicyWithInvalidSettingsIsRejected(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.Enabled = false
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), brokenRegistry(t), newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), consoleWriteBody(existing, false)); err == nil {
		t.Fatal("expected validation error when editing an already-paused policy")
	}
}

// A slug change points an MCP-wide policy at another plugin, and one that does
// not run on MCP would leave the policy placed where it can never run.
func TestUpdater_Update_SlugChangeOfAnMCPWidePolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		scope     *domain.MCPScope
		slug      func(existing *domain.Policy) string
		protocols []appplugins.Protocol
		wantErr   error
	}{
		{
			name:      "to a plugin without MCP is refused",
			slug:      func(*domain.Policy) string { return "semantic_cache" },
			protocols: []appplugins.Protocol{appplugins.ProtocolLLM},
			wantErr:   domain.ErrMCPWideUnsupported,
		},
		{
			name:      "to a plugin without MCP is refused for the placement before the scope",
			scope:     &domain.MCPScope{Groups: []string{"Finanzas"}},
			slug:      func(*domain.Policy) string { return "semantic_cache" },
			protocols: []appplugins.Protocol{appplugins.ProtocolLLM},
			wantErr:   domain.ErrMCPWideUnsupported,
		},
		{
			name:      "to a plugin with MCP lands",
			slug:      func(*domain.Policy) string { return "trustguard" },
			protocols: []appplugins.Protocol{appplugins.ProtocolLLM, appplugins.ProtocolMCP},
		},
		{
			name:      "echoing the stored slug is not a change",
			slug:      func(existing *domain.Policy) string { return existing.Slug },
			protocols: []appplugins.Protocol{appplugins.ProtocolLLM},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := repomocks.NewRepository(t)
			existing := existingPolicy(t)
			existing.SetMCPWide(true)
			existing.MCPScope = tt.scope
			repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
			publisher := cachemocks.NewEventPublisher(t)
			if tt.wantErr == nil {
				repo.EXPECT().Update(mock.Anything, mock.Anything, false).Return(nil).Once()
				publisher = expectInvalidation(t, existing.GatewayID)
			}

			updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t),
				newScopedRegistryMock(t, tt.protocols...), newCacheManager(), publisher, newTestLogger(), nil)
			_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
				ID:   existing.ID,
				Slug: ptr(tt.slug(existing)),
			})
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Update error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) || !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("err = %v, want %v wrapping ErrValidation", err, tt.wantErr)
			}
			if errors.Is(err, domain.ErrInvalidMCPScope) {
				t.Fatalf("err = %v, want the placement refusal, not the scope one", err)
			}
			repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The links of a global policy are ignored at load, but demoting it brings them
// back and the demotion checks nothing. So a scope that does not reach a linked
// LLM consumer is refused here too, as on a targeted policy.
func TestUpdater_Update_GlobalScopeIsCheckedAgainstItsLinks(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	consumerID := ids.New[ids.ConsumerKind]()
	existing.ConsumerIDs = []ids.ConsumerID{consumerID}
	existing.SetGlobal(true)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	jira := ids.New[ids.RegistryKind]()
	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, existing.GatewayID, sameRegistryIDs(jira)).
		Return([]*registrydomain.Registry{mcpRegistry(existing.GatewayID, jira)}, nil).
		Once()

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().
		FindByID(mock.Anything, consumerID).
		Return(&consumerdomain.Consumer{ID: consumerID, Type: consumerdomain.TypeLLM}, nil).
		Once()

	updater := apppolicy.NewUpdater(
		repo, consumers, freeLevels(t), registryRepo,
		newScopedRegistryMock(t, appplugins.ProtocolLLM, appplugins.ProtocolMCP),
		newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil,
	)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:       existing.ID,
		MCPScope: apppolicy.MCPScopePatch{Set: true, Value: &domain.MCPScope{RegistryIDs: []ids.RegistryID{jira}}},
	})
	if !errors.Is(err, consumerdomain.ErrPolicyScopeDoesNotCross) || !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrPolicyScopeDoesNotCross wrapping ErrValidation", err)
	}
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}
