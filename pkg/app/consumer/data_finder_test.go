package consumer_test

import (
	"context"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	authmocks "github.com/NeuralTrust/AgentGateway/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	policymocks "github.com/NeuralTrust/AgentGateway/pkg/domain/policy/mocks"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	backendmocks "github.com/NeuralTrust/AgentGateway/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
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
		RoutingMode: domain.RoutingModeInline,
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

	finder := appconsumer.NewDataFinder(repo, registryRepo, policyRepo, authRepo, nil, nil, newCacheManager(), newTestLogger())

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

func TestDataFinder_FindByGateway_ResolvesFallbackChainInOrder(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	poolID := ids.New[ids.RegistryKind]()
	fb1, fb2 := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	now := time.Now().UTC()
	cons := domain.Rehydrate(domain.RehydrateParams{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gwID,
		Name:        "c",
		Type:        domain.TypeLLM,
		Slug:        "X84Yhsy8",
		RoutingMode: domain.RoutingModeInline,
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
			{ID: poolID, GatewayID: gwID, LLMTarget: &registrydomain.LLMTarget{Provider: "openai"}},
			{ID: fb1, GatewayID: gwID, LLMTarget: &registrydomain.LLMTarget{Provider: "anthropic"}},
			{ID: fb2, GatewayID: gwID, LLMTarget: &registrydomain.LLMTarget{Provider: "mistral"}},
		}, nil).Once()

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Once()

	finder := appconsumer.NewDataFinder(
		repo, registryRepo,
		policyRepo, authmocks.NewRepository(t),
		nil, nil, newCacheManager(), newTestLogger(),
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

func TestDataFinder_FindByGateway_CacheHitSkipsRepositories(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	mgr := newCacheManager()
	cached := &appconsumer.Data{GatewayID: gwID}
	mgr.GetTTLMap(cache.ConsumerDataTTLName).Set(gwID.String(), cached)

	finder := appconsumer.NewDataFinder(
		repomocks.NewRepository(t), backendmocks.NewRepository(t),
		policymocks.NewRepository(t), authmocks.NewRepository(t),
		nil, nil, mgr, newTestLogger(),
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
		nil, nil, mgr, newTestLogger(),
	)

	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	if len(data.Consumers) != 0 {
		t.Fatalf("expected empty aggregate, got %d consumers", len(data.Consumers))
	}
}
