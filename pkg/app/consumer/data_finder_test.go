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

func routableConsumer(gwID ids.GatewayID, policyIDs []ids.PolicyID, authIDs []ids.AuthID) *domain.Consumer {
	now := time.Now().UTC()
	return domain.Rehydrate(
		ids.New[ids.ConsumerKind](), gwID, "c", domain.TypeLLM,
		"/v1/chat", "round-robin", nil,
		nil, true,
		[]ids.RegistryID{ids.New[ids.RegistryKind]()}, policyIDs, authIDs,
		nil,
		nil,
		now, now,
	)
}

func TestDataFinder_FindByGateway_BuildsAggregateAndCaches(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	pid := ids.New[ids.PolicyKind]()
	aid := ids.New[ids.AuthKind]()
	withAuth := routableConsumer(gwID, []ids.PolicyID{pid}, []ids.AuthID{aid})
	policyOnly := routableConsumer(gwID, []ids.PolicyID{pid}, nil)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*domain.Consumer{withAuth, policyOnly}, nil).Once()

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.MatchedBy(func(pids []ids.PolicyID) bool {
			return len(pids) == 1 && pids[0] == pid
		})).
		Return([]*policydomain.Policy{{ID: pid, GatewayID: gwID}}, nil).Once()

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

	finder := appconsumer.NewDataFinder(repo, registryRepo, policyRepo, authRepo, newCacheManager(), newTestLogger())

	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	if len(data.Consumers) != 2 {
		t.Fatalf("expected 2 consumers, got %d", len(data.Consumers))
	}

	if data.Consumers[0].Consumer.ID != withAuth.ID {
		t.Fatal("expected repository order to be preserved")
	}
	if data.Consumers[1].Consumer.ID != policyOnly.ID {
		t.Fatal("expected repository order to be preserved")
	}
	if len(data.Consumers[0].Policies) != 1 || data.Consumers[0].Policies[0].ID != pid {
		t.Fatal("consumer did not resolve its policy")
	}
	if len(data.Consumers[0].Auths) != 1 || data.Consumers[0].Auths[0].ID != aid {
		t.Fatal("consumer did not resolve its auth")
	}
	if len(data.Consumers[1].Auths) != 0 {
		t.Fatal("policy-only consumer must not resolve any auth")
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
	cons := domain.Rehydrate(
		ids.New[ids.ConsumerKind](), gwID, "c", domain.TypeLLM,
		"/v1/chat", "round-robin", nil,
		nil, true,
		[]ids.RegistryID{poolID}, nil, nil,
		&domain.Fallback{
			Enabled:  true,
			Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
			Budget:   domain.FallbackBudget{MaxAttempts: 9},

			Chain: []ids.RegistryID{fb2, fb1},
		},
		nil,
		now, now,
	)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Consumer{cons}, nil).Once()

	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.MatchedBy(func(bids []ids.RegistryID) bool {
			return len(bids) == 3
		})).
		Return([]*registrydomain.Registry{
			{ID: poolID, GatewayID: gwID, Provider: "openai"},
			{ID: fb1, GatewayID: gwID, Provider: "anthropic"},
			{ID: fb2, GatewayID: gwID, Provider: "mistral"},
		}, nil).Once()

	finder := appconsumer.NewDataFinder(
		repo, registryRepo,
		policymocks.NewRepository(t), authmocks.NewRepository(t),
		newCacheManager(), newTestLogger(),
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
		mgr, newTestLogger(),
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

	finder := appconsumer.NewDataFinder(
		repo, backendmocks.NewRepository(t),
		policymocks.NewRepository(t), authmocks.NewRepository(t),
		mgr, newTestLogger(),
	)

	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	if len(data.Consumers) != 0 {
		t.Fatalf("expected empty aggregate, got %d consumers", len(data.Consumers))
	}
}
