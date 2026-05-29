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
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	policymocks "github.com/NeuralTrust/AgentGateway/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func routableConsumer(gwID uuid.UUID, policyIDs, authIDs []uuid.UUID) *domain.Consumer {
	now := time.Now().UTC()
	return domain.Rehydrate(
		uuid.New(), gwID, "c", domain.TypeLLM,
		nil, true,
		[]uuid.UUID{uuid.New()}, policyIDs, authIDs,
		now, now,
	)
}

func TestDataFinder_FindByGateway_BuildsAggregateAndCaches(t *testing.T) {
	t.Parallel()
	gwID := uuid.New()
	pid := uuid.New()
	aid := uuid.New()
	withAuth := routableConsumer(gwID, []uuid.UUID{pid}, []uuid.UUID{aid})
	policyOnly := routableConsumer(gwID, []uuid.UUID{pid}, nil)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*domain.Consumer{withAuth, policyOnly}, nil).Once()

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.MatchedBy(func(ids []uuid.UUID) bool {
			return len(ids) == 1 && ids[0] == pid
		})).
		Return([]*policydomain.Policy{{ID: pid, GatewayID: gwID}}, nil).Once()

	authRepo := authmocks.NewRepository(t)
	authRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.MatchedBy(func(ids []uuid.UUID) bool {
			return len(ids) == 1 && ids[0] == aid
		})).
		Return([]*authdomain.Auth{{ID: aid, GatewayID: gwID}}, nil).Once()

	finder := appconsumer.NewDataFinder(repo, policyRepo, authRepo, newCacheManager(), newTestLogger())

	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("FindByGateway error: %v", err)
	}
	if len(data.Consumers) != 2 {
		t.Fatalf("expected 2 consumers, got %d", len(data.Consumers))
	}
	// Order is preserved from the repository (no path-specificity sorting).
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

	// Second call must be served from the in-process cache: the .Once()
	// expectations above would fail if any repository were queried again.
	again, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("second FindByGateway error: %v", err)
	}
	if again != data {
		t.Fatal("expected the cached aggregate to be returned on the second call")
	}
}

func TestDataFinder_FindByGateway_CacheHitSkipsRepositories(t *testing.T) {
	t.Parallel()
	gwID := uuid.New()
	mgr := newCacheManager()
	cached := &appconsumer.Data{GatewayID: gwID}
	mgr.GetTTLMap(cache.ConsumerDataTTLName).Set(gwID.String(), cached)

	finder := appconsumer.NewDataFinder(
		repomocks.NewRepository(t), policymocks.NewRepository(t), authmocks.NewRepository(t),
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
	gwID := uuid.New()
	mgr := newCacheManager()
	mgr.GetTTLMap(cache.ConsumerDataTTLName).Set(gwID.String(), "not-a-consumer-data")

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Consumer{}, nil).Once()

	finder := appconsumer.NewDataFinder(
		repo, policymocks.NewRepository(t), authmocks.NewRepository(t),
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
