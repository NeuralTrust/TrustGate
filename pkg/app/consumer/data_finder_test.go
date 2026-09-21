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

package consumer_test

import (
	"context"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	policymocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	backendmocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pertoolratelimit"
	"github.com/stretchr/testify/mock"
)

func routableConsumer(gwID ids.GatewayID, authIDs []ids.AuthID) *domain.Consumer {
	now := time.Now().UTC()
	return domain.Rehydrate(domain.RehydrateParams{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gwID,
		Name:        "c",
		Type:        domain.TypeLLM,
		Slug:        "X84Yhsy8",
		Active:      true,
		RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()},
		AuthIDs:     authIDs,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
}

func hasPolicySlug(policies []*policydomain.Policy, slug string) bool {
	for _, p := range policies {
		if p.Slug == slug {
			return true
		}
	}
	return false
}

func TestDataFinder_FindByGateway_ComposesGlobalAndConsumerPolicies(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	aid := ids.New[ids.AuthKind]()
	withAuth := routableConsumer(gwID, []ids.AuthID{aid})
	plain := routableConsumer(gwID, nil)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*domain.Consumer{withAuth, plain}, nil).Once()

	globalAudit := &policydomain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "audit", Global: true}
	globalRate := &policydomain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "ratelimit", Global: true}
	rateForC1 := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "ratelimit",
		ConsumerIDs: []ids.ConsumerID{withAuth.ID},
	}
	multi := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "multi",
		ConsumerIDs: []ids.ConsumerID{withAuth.ID, plain.ID},
	}

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*policydomain.Policy{globalAudit, globalRate, rateForC1, multi}, nil).Once()

	authRepo := authmocks.NewRepository(t)
	authRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.MatchedBy(func(aids []ids.AuthID) bool {
			return len(aids) == 1 && aids[0] == aid
		})).
		Return([]*authdomain.Auth{{ID: aid, GatewayID: gwID}}, nil).Once()

	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.Anything).
		Return(nil, nil).Once()

	finder := appconsumer.NewDataFinder(repo, registryRepo, policyRepo, authRepo, nil, newCacheManager(), newTestLogger())

	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	if len(data.Consumers) != 2 {
		t.Fatalf("expected 2 consumers, got %d", len(data.Consumers))
	}

	c1 := data.Consumers[0]
	if c1.Consumer.ID != withAuth.ID {
		t.Fatal("expected repository order to be preserved")
	}
	if len(c1.Policies) != 3 {
		t.Fatalf("withAuth expected 3 policies, got %d", len(c1.Policies))
	}
	for _, p := range c1.Policies {
		if p.Slug == "ratelimit" && p.ID != rateForC1.ID {
			t.Fatal("global ratelimit should have been overridden by the consumer-scoped one")
		}
	}
	if !hasPolicySlug(c1.Policies, "audit") || !hasPolicySlug(c1.Policies, "multi") {
		t.Fatalf("withAuth missing expected policies: %+v", c1.Policies)
	}
	if len(c1.Auths) != 1 || c1.Auths[0].ID != aid {
		t.Fatal("consumer did not resolve its auth")
	}

	c2 := data.Consumers[1]
	if c2.Consumer.ID != plain.ID {
		t.Fatal("expected repository order to be preserved")
	}
	if len(c2.Policies) != 3 {
		t.Fatalf("plain expected 3 policies, got %d", len(c2.Policies))
	}
	if !hasPolicySlug(c2.Policies, "audit") || !hasPolicySlug(c2.Policies, "ratelimit") || !hasPolicySlug(c2.Policies, "multi") {
		t.Fatalf("plain missing expected policies: %+v", c2.Policies)
	}
	for _, p := range c2.Policies {
		if p.Slug == "ratelimit" && p.ID != globalRate.ID {
			t.Fatal("plain should keep the global ratelimit policy")
		}
	}
	if len(c2.Auths) != 0 {
		t.Fatal("plain consumer must not resolve any auth")
	}

	again, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("second FindByGateway error: %v", err)
	}
	if again != data {
		t.Fatal("expected the cached aggregate to be returned on the second call")
	}
}

func TestDataFinder_FindByGateway_AppliesGlobalPoliciesToStoreConsumer(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	globalPolicy := &policydomain.Policy{
		ID:        ids.New[ids.PolicyKind](),
		GatewayID: gwID,
		Slug:      "per_tool_rate_limiter",
		Enabled:   true,
		Global:    true,
		Stages:    []policydomain.Stage{policydomain.StagePreRequest},
	}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Once()
	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*policydomain.Policy{globalPolicy}, nil).Once()

	pluginRegistry := appplugins.NewRegistry()
	if err := pluginRegistry.Register(pertoolratelimit.New(nil, nil)); err != nil {
		t.Fatalf("register plugin: %v", err)
	}
	finder := appconsumer.NewDataFinder(
		repo,
		backendmocks.NewRepository(t),
		policyRepo,
		authmocks.NewRepository(t),
		pluginRegistry,
		newCacheManager(),
		newTestLogger(),
	)

	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	if data.StoreConsumer == nil || !domain.IsStoreConsumer(data.StoreConsumer.Consumer) {
		t.Fatal("expected the aggregate to contain the synthetic Store consumer")
	}
	if len(data.StoreConsumer.Policies) != 1 || data.StoreConsumer.Policies[0].ID != globalPolicy.ID {
		t.Fatalf("Store policies = %+v, want global policy %s", data.StoreConsumer.Policies, globalPolicy.ID)
	}
	if data.StoreConsumer.PolicyPlan == nil || !data.StoreConsumer.PolicyPlan.Has(policydomain.StagePreRequest) {
		t.Fatal("expected the Store policy plan to contain the global pre-request policy")
	}
	if len(data.Consumers) != 0 {
		t.Fatalf("synthetic Store consumer must not appear in persisted consumers: %+v", data.Consumers)
	}
}

func TestDataFinder_FindByGateway_ResolvesFallbackChainInOrder(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	poolID := ids.New[ids.RegistryKind]()
	fb1, fb2 := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	now := time.Now().UTC()
	cons := domain.Rehydrate(domain.RehydrateParams{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Name:      "c",
		Type:      domain.TypeLLM,
		Slug:      "X84Yhsy8",
		Fallback: &domain.Fallback{
			Enabled:  true,
			Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
			Budget:   domain.FallbackBudget{MaxAttempts: 9},
			Chain:    []ids.RegistryID{fb2, fb1},
		},
		Active:      true,
		RegistryIDs: []ids.RegistryID{poolID},
		CreatedAt:   now,
		UpdatedAt:   now,
	})

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Consumer{cons}, nil).Once()

	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.MatchedBy(func(bids []ids.RegistryID) bool {
			return len(bids) == 3
		})).
		Return([]*registrydomain.Registry{
			{ID: poolID, GatewayID: gwID, Enabled: true, LLMTarget: &registrydomain.LLMTarget{Provider: "openai"}},
			{ID: fb1, GatewayID: gwID, Enabled: true, LLMTarget: &registrydomain.LLMTarget{Provider: "anthropic"}},
			{ID: fb2, GatewayID: gwID, Enabled: true, LLMTarget: &registrydomain.LLMTarget{Provider: "mistral"}},
		}, nil).Once()

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Once()

	finder := appconsumer.NewDataFinder(
		repo, registryRepo,
		policyRepo, authmocks.NewRepository(t),
		nil, newCacheManager(), newTestLogger(),
	)

	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	rc := data.Consumers[0]
	if len(rc.Registries) != 1 || rc.Registries[0].ID != poolID {
		t.Fatalf("pool registries not resolved: %+v", rc.Registries)
	}
	if len(rc.FallbackBackends) != 2 {
		t.Fatalf("expected 2 fallback registries, got %d", len(rc.FallbackBackends))
	}
	if rc.FallbackBackends[0].ID != fb2 || rc.FallbackBackends[1].ID != fb1 {
		t.Fatal("fallback chain order was not preserved")
	}
}

func TestDataFinder_FindByGateway_ExcludesDisabledRegistries(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	poolID := ids.New[ids.RegistryKind]()
	disabledPoolID := ids.New[ids.RegistryKind]()
	fbEnabled, fbDisabled := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	now := time.Now().UTC()
	cons := domain.Rehydrate(domain.RehydrateParams{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Name:      "c",
		Type:      domain.TypeLLM,
		Slug:      "X84Yhsy8",
		Fallback: &domain.Fallback{
			Enabled:  true,
			Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
			Budget:   domain.FallbackBudget{MaxAttempts: 9},
			Chain:    []ids.RegistryID{fbDisabled, fbEnabled},
		},
		Active:      true,
		RegistryIDs: []ids.RegistryID{poolID, disabledPoolID},
		CreatedAt:   now,
		UpdatedAt:   now,
	})

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Consumer{cons}, nil).Once()

	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.Anything).
		Return([]*registrydomain.Registry{
			{ID: poolID, GatewayID: gwID, Enabled: true, LLMTarget: &registrydomain.LLMTarget{Provider: "openai"}},
			{ID: disabledPoolID, GatewayID: gwID, Enabled: false, LLMTarget: &registrydomain.LLMTarget{Provider: "anthropic"}},
			{ID: fbEnabled, GatewayID: gwID, Enabled: true, LLMTarget: &registrydomain.LLMTarget{Provider: "mistral"}},
			{ID: fbDisabled, GatewayID: gwID, Enabled: false, LLMTarget: &registrydomain.LLMTarget{Provider: "google"}},
		}, nil).Once()

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Once()

	finder := appconsumer.NewDataFinder(
		repo, registryRepo,
		policyRepo, authmocks.NewRepository(t),
		nil, newCacheManager(), newTestLogger(),
	)

	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	rc := data.Consumers[0]
	if len(rc.Registries) != 1 || rc.Registries[0].ID != poolID {
		t.Fatalf("disabled pool registry not excluded: %+v", rc.Registries)
	}
	if len(rc.FallbackBackends) != 1 || rc.FallbackBackends[0].ID != fbEnabled {
		t.Fatalf("disabled fallback registry not excluded: %+v", rc.FallbackBackends)
	}
	if _, ok := data.RegistryByID(disabledPoolID); ok {
		t.Fatal("disabled registry must not be in the RegistryByID index")
	}
	if _, ok := data.RegistryByID(fbDisabled); ok {
		t.Fatal("disabled fallback registry must not be in the RegistryByID index")
	}
	if _, ok := data.RegistryByID(poolID); !ok {
		t.Fatal("enabled registry must be in the RegistryByID index")
	}
}

func TestDataFinder_FindByGateway_CacheHitSkipsRepositories(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	mgr := newCacheManager()
	cached := &appconsumer.Data{GatewayID: gwID}
	mgr.GetTTLMap(cache.ConsumerDataTTLName).Set(gwID.String(), cached)

	finder := appconsumer.NewDataFinder(
		repomocks.NewRepository(t), backendmocks.NewRepository(t),
		policymocks.NewRepository(t), authmocks.NewRepository(t),
		nil, mgr, newTestLogger(),
	)

	got, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	if got != cached {
		t.Fatal("expected the cached aggregate pointer to be returned")
	}
}

func TestDataFinder_FindByGateway_RecoversFromCorruptCacheEntry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	mgr := newCacheManager()
	mgr.GetTTLMap(cache.ConsumerDataTTLName).Set(gwID.String(), "not-a-consumer-data")

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Consumer{}, nil).Once()

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Once()

	finder := appconsumer.NewDataFinder(
		repo, backendmocks.NewRepository(t),
		policyRepo, authmocks.NewRepository(t),
		nil, mgr, newTestLogger(),
	)

	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	if len(data.Consumers) != 0 {
		t.Fatalf("expected empty aggregate, got %d consumers", len(data.Consumers))
	}
}

func policyIDs(policies []*policydomain.Policy) []ids.PolicyID {
	out := make([]ids.PolicyID, 0, len(policies))
	for _, p := range policies {
		out = append(out, p.ID)
	}
	return out
}

func containsPolicyID(policies []*policydomain.Policy, id ids.PolicyID) bool {
	for _, p := range policies {
		if p.ID == id {
			return true
		}
	}
	return false
}

func TestDataFinder_FindByGateway_SlugOverrideOnlyAmongUnscopedPolicies(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	scopedConsumer := routableConsumer(gwID, nil)
	unscopedConsumer := routableConsumer(gwID, nil)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*domain.Consumer{scopedConsumer, unscopedConsumer}, nil).Once()

	globalGuard := &policydomain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "trustguard", Global: true}
	globalGuardScoped := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "trustguard", Global: true,
		MCPScope: &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{registryID}},
	}
	consumerGuardScoped := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "trustguard",
		ConsumerIDs: []ids.ConsumerID{scopedConsumer.ID},
		MCPScope:    &policydomain.MCPScope{Groups: []string{"Finanzas"}},
	}
	consumerGuard := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "trustguard",
		ConsumerIDs: []ids.ConsumerID{unscopedConsumer.ID},
	}

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*policydomain.Policy{globalGuard, globalGuardScoped, consumerGuardScoped, consumerGuard}, nil).Once()

	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().FindByIDs(mock.Anything, gwID, mock.Anything).Return(nil, nil).Once()

	finder := appconsumer.NewDataFinder(repo, registryRepo, policyRepo, authmocks.NewRepository(t), nil, newCacheManager(), newTestLogger())
	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	if len(data.Consumers) != 2 {
		t.Fatalf("expected 2 consumers, got %d", len(data.Consumers))
	}

	withScoped := data.Consumers[0]
	if len(withScoped.Policies) != 1 || withScoped.Policies[0].ID != globalGuard.ID {
		t.Fatalf("a scoped consumer policy must not suppress the unscoped global of the same slug, got %v", policyIDs(withScoped.Policies))
	}
	if len(withScoped.ScopedPolicies) != 2 ||
		!containsPolicyID(withScoped.ScopedPolicies, consumerGuardScoped.ID) ||
		!containsPolicyID(withScoped.ScopedPolicies, globalGuardScoped.ID) {
		t.Fatalf("scoped policies must be additive (consumer + global), got %v", policyIDs(withScoped.ScopedPolicies))
	}
	if withScoped.ScopedPolicies[0].ID != consumerGuardScoped.ID {
		t.Fatal("consumer-scoped policies must precede global ones in ScopedPolicies")
	}

	withUnscoped := data.Consumers[1]
	if len(withUnscoped.Policies) != 1 || withUnscoped.Policies[0].ID != consumerGuard.ID {
		t.Fatalf("the unscoped consumer policy must still override the unscoped global, got %v", policyIDs(withUnscoped.Policies))
	}
	if len(withUnscoped.ScopedPolicies) != 1 || withUnscoped.ScopedPolicies[0].ID != globalGuardScoped.ID {
		t.Fatalf("an unscoped consumer policy must never suppress a scoped global, got %v", policyIDs(withUnscoped.ScopedPolicies))
	}
}

// The dimension decides, not the presence of a scope. A registry scope and a
// tombstone stay out of the non-MCP plane; a group-only scope on an inert-safe
// plugin is folded in (RUN-1621, §2.1).
func TestDataFinder_FindByGateway_DestinationScopedPoliciesStayOutOfTheNonMCPPlan(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	cons := routableConsumer(gwID, nil)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Consumer{cons}, nil).Once()

	byRegistry := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "per_tool_rate_limiter", Enabled: true,
		ConsumerIDs: []ids.ConsumerID{cons.ID},
		Stages:      []policydomain.Stage{policydomain.StagePreRequest},
		MCPScope:    &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()}},
	}
	pruned := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "per_tool_rate_limiter", Enabled: true,
		ConsumerIDs: []ids.ConsumerID{cons.ID},
		Stages:      []policydomain.Stage{policydomain.StagePreRequest},
		MCPScope:    &policydomain.MCPScope{},
	}
	byGroup := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Name: "G", Slug: inertSafeSlug, Enabled: true,
		ConsumerIDs: []ids.ConsumerID{cons.ID},
		Stages:      []policydomain.Stage{policydomain.StagePreRequest},
		MCPScope:    &policydomain.MCPScope{Groups: []string{"finance"}},
	}
	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*policydomain.Policy{byRegistry, pruned, byGroup}, nil).Once()

	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().FindByIDs(mock.Anything, gwID, mock.Anything).Return(nil, nil).Once()

	h := newInertHarness(t)
	if err := h.reg.Register(pertoolratelimit.New(nil, nil)); err != nil {
		t.Fatalf("register plugin: %v", err)
	}
	finder := appconsumer.NewDataFinder(repo, registryRepo, policyRepo, authmocks.NewRepository(t), h.reg, newCacheManager(), newTestLogger())
	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	rc := data.Consumers[0]
	if containsPolicyID(rc.Policies, byRegistry.ID) || containsPolicyID(rc.Policies, pruned.ID) {
		t.Fatalf("a registry scope and a tombstone must not enter Policies, got %v", policyIDs(rc.Policies))
	}
	if len(rc.Policies) != 1 || rc.Policies[0].ID != byGroup.ID {
		t.Fatalf("the group-only policy must enter Policies, got %v", policyIDs(rc.Policies))
	}
	if rc.PolicyPlan == nil {
		t.Fatal("a non-MCP consumer must always carry a plan, or the executor rebuilds the chain unflattened")
	}
	if got := h.executedPlan(rc.PolicyPlan); len(got) != 1 || got[0] != "G" {
		t.Fatalf("the inert plan must run the group-only policy and nothing else, got %v", got)
	}
	if len(rc.ScopedPolicies) != 3 {
		t.Fatalf("every scoped policy must still be kept as scoped, got %v", policyIDs(rc.ScopedPolicies))
	}
}

func TestDataFinder_FindByGateway_StoreConsumerPartitionsGlobalPolicies(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	unscoped := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "per_tool_rate_limiter", Enabled: true, Global: true,
		Stages: []policydomain.Stage{policydomain.StagePreRequest},
	}
	scopedGlobal := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "per_tool_rate_limiter", Enabled: true, Global: true,
		Stages:   []policydomain.Stage{policydomain.StagePreRequest},
		MCPScope: &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()}},
	}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Once()
	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*policydomain.Policy{scopedGlobal, unscoped}, nil).Once()

	pluginRegistry := appplugins.NewRegistry()
	if err := pluginRegistry.Register(pertoolratelimit.New(nil, nil)); err != nil {
		t.Fatalf("register plugin: %v", err)
	}
	finder := appconsumer.NewDataFinder(repo, backendmocks.NewRepository(t), policyRepo, authmocks.NewRepository(t), pluginRegistry, newCacheManager(), newTestLogger())
	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	store := data.StoreConsumer
	if store == nil {
		t.Fatal("expected the synthetic Store consumer")
	}
	if len(store.Policies) != 1 || store.Policies[0].ID != unscoped.ID {
		t.Fatalf("Store.Policies must hold only unscoped globals, got %v", policyIDs(store.Policies))
	}
	if len(store.ScopedPolicies) != 1 || store.ScopedPolicies[0].ID != scopedGlobal.ID {
		t.Fatalf("scoped globals must reach the Store as ScopedPolicies, got %v", policyIDs(store.ScopedPolicies))
	}
	if store.PolicyPlan == nil || !store.PolicyPlan.Has(policydomain.StagePreRequest) {
		t.Fatal("the Store base plan must still carry the unscoped global")
	}
}

func mcpRoutableConsumer(gwID ids.GatewayID, registryIDs ...ids.RegistryID) *domain.Consumer {
	now := time.Now().UTC()
	return domain.Rehydrate(domain.RehydrateParams{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gwID,
		Name:        "mcp",
		Type:        domain.TypeMCP,
		Slug:        "M84Yhsy8",
		Active:      true,
		RegistryIDs: registryIDs,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
}

// Promotion to global is not a back door: a destination scope stays MCP-only
// however it arrived, while a group-only global reaches every plane
// (RUN-1621, rule 7).
func TestDataFinder_FindByGateway_MCPPlansAreMCPOnlyAndGlobalDestinationScopeNeverCrosses(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	snowflakeID := ids.New[ids.RegistryKind]()
	mcpCons := mcpRoutableConsumer(gwID, snowflakeID)
	llmCons := routableConsumer(gwID, nil)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*domain.Consumer{mcpCons, llmCons}, nil).Once()

	scoped := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "per_tool_rate_limiter", Enabled: true,
		ConsumerIDs: []ids.ConsumerID{mcpCons.ID, llmCons.ID},
		Stages:      []policydomain.Stage{policydomain.StagePreRequest},
		MCPScope:    &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{snowflakeID}},
	}
	globalByRegistry := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Name: "R", Slug: nameGatingSlug, Enabled: true, Global: true,
		Stages:   []policydomain.Stage{policydomain.StagePreRequest},
		MCPScope: &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{snowflakeID}},
	}
	globalByGroup := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Name: "G", Slug: inertSafeSlug, Enabled: true, Global: true,
		Stages:   []policydomain.Stage{policydomain.StagePreRequest},
		MCPScope: &policydomain.MCPScope{Groups: []string{"finance"}},
	}
	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*policydomain.Policy{scoped, globalByRegistry, globalByGroup}, nil).Once()

	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().FindByIDs(mock.Anything, gwID, mock.Anything).Return(nil, nil).Once()

	h := newInertHarness(t)
	if err := h.reg.Register(pertoolratelimit.New(nil, nil)); err != nil {
		t.Fatalf("register plugin: %v", err)
	}
	finder := appconsumer.NewDataFinder(repo, registryRepo, policyRepo, authmocks.NewRepository(t), h.reg, newCacheManager(), newTestLogger())
	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	if len(data.Consumers) != 2 {
		t.Fatalf("expected 2 consumers, got %d", len(data.Consumers))
	}

	mcp := data.Consumers[0]
	if mcp.MCPPlans == nil {
		t.Fatal("an MCP consumer must carry precompiled MCPPlans")
	}
	if mcp.PolicyPlan == nil || mcp.PolicyPlan.Has(policydomain.StagePreRequest) {
		t.Fatal("the base PolicyPlan must still exclude scoped policies")
	}
	snowflake := &registrydomain.Registry{ID: snowflakeID, GatewayID: gwID, Enabled: true}
	if plan := mcp.MCPPlans.PlanFor(snowflake, "run_query", nil); plan == nil || !plan.Has(policydomain.StagePreRequest) {
		t.Fatal("PlanFor on the scoped registry must include the scoped policy")
	}
	other := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gwID, Enabled: true}
	if plan := mcp.MCPPlans.PlanFor(other, "run_query", nil); plan == nil || plan.Has(policydomain.StagePreRequest) {
		t.Fatal("PlanFor on another registry must fall back to the base plan")
	}

	llm := data.Consumers[1]
	if llm.MCPPlans != nil {
		t.Fatal("LLM consumers must not carry MCPPlans")
	}
	if containsPolicyID(llm.Policies, globalByRegistry.ID) || containsPolicyID(llm.Policies, scoped.ID) {
		t.Fatalf("a destination scope must not cross, global or attached, got %v", policyIDs(llm.Policies))
	}
	if len(llm.Policies) != 1 || llm.Policies[0].ID != globalByGroup.ID {
		t.Fatalf("a group-only global must reach every plane, got %v", policyIDs(llm.Policies))
	}
}

func TestDataFinder_FindByGateway_StoreConsumerPlansFromScopedGlobals(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	snowflakeID := ids.New[ids.RegistryKind]()
	scopedGlobal := &policydomain.Policy{
		ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Slug: "per_tool_rate_limiter", Enabled: true, Global: true,
		Stages:   []policydomain.Stage{policydomain.StagePreRequest},
		MCPScope: &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{snowflakeID}},
	}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Once()
	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*policydomain.Policy{scopedGlobal}, nil).Once()

	pluginRegistry := appplugins.NewRegistry()
	if err := pluginRegistry.Register(pertoolratelimit.New(nil, nil)); err != nil {
		t.Fatalf("register plugin: %v", err)
	}
	finder := appconsumer.NewDataFinder(repo, backendmocks.NewRepository(t), policyRepo, authmocks.NewRepository(t), pluginRegistry, newCacheManager(), newTestLogger())
	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	store := data.StoreConsumer
	if store == nil || store.MCPPlans == nil {
		t.Fatal("the Store consumer must carry MCPPlans built from the global policies")
	}
	if store.PolicyPlan == nil || store.PolicyPlan.Has(policydomain.StagePreRequest) {
		t.Fatal("the Store base plan must exclude scoped globals")
	}
	snowflake := &registrydomain.Registry{ID: snowflakeID, GatewayID: gwID, Enabled: true}
	if plan := store.MCPPlans.PlanFor(snowflake, "run_query", nil); plan == nil || !plan.Has(policydomain.StagePreRequest) {
		t.Fatal("a scoped global must reach the Store plan for its registry")
	}
	other := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gwID, Enabled: true}
	if plan := store.MCPPlans.PlanFor(other, "run_query", nil); plan == nil || plan.Has(policydomain.StagePreRequest) {
		t.Fatal("a scoped global must not reach other registries in the Store")
	}
}
