package consumer_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authmocks "github.com/NeuralTrust/AgentGateway/pkg/domain/auth/mocks"
	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	backendmocks "github.com/NeuralTrust/AgentGateway/pkg/domain/backend/mocks"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer/mocks"
	policymocks "github.com/NeuralTrust/AgentGateway/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

func newBackendStub(gwID, beID uuid.UUID) *backendmocks.Repository {
	t := &backendmocks.Repository{}
	t.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.Anything).
		Return([]*backenddomain.Backend{{ID: beID, GatewayID: gwID}}, nil).
		Maybe()
	return t
}

func newPolicyStub() *policymocks.Repository {
	return &policymocks.Repository{}
}

func newAuthStub() *authmocks.Repository {
	return &authmocks.Repository{}
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	gwID, beID := uuid.New(), uuid.New()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.GatewayID == gwID && c.Name == "chat" && c.Type == domain.TypeLLM
		})).
		Return(nil).
		Once()

	beRepo := newBackendStub(gwID, beID)
	mgr := newCacheManager()
	creator := appconsumer.NewCreator(repo, beRepo, newPolicyStub(), newAuthStub(), mgr, cachetest.NoopPublisher(), newTestLogger())

	c, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:  gwID,
		Name:       "chat",
		Type:       domain.TypeLLM,
		BackendIDs: []uuid.UUID{beID},
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	cached, ok := mgr.GetTTLMap(cache.ConsumerTTLName).Get(c.ID.String())
	if !ok {
		t.Fatal("created consumer was not pre-warmed in the cache")
	}
	if cached.(*domain.Consumer).ID != c.ID {
		t.Fatal("cached consumer ID mismatch")
	}
}

func TestCreator_Create_RejectsBackendFromOtherGateway(t *testing.T) {
	t.Parallel()
	gwID, beID := uuid.New(), uuid.New()

	repo := repomocks.NewRepository(t)
	beRepo := &backendmocks.Repository{}
	beRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.Anything).
		Return([]*backenddomain.Backend{}, nil).
		Once()

	creator := appconsumer.NewCreator(repo, beRepo, newPolicyStub(), newAuthStub(), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:  gwID,
		Name:       "x",
		Type:       domain.TypeLLM,
		BackendIDs: []uuid.UUID{beID},
	})
	if !errors.Is(err, domain.ErrInvalidBackendID) {
		t.Fatalf("err = %v, want ErrInvalidBackendID", err)
	}
}

func TestCreator_Create_RejectsInvalidDomain(t *testing.T) {
	t.Parallel()
	gwID, beID := uuid.New(), uuid.New()
	beRepo := newBackendStub(gwID, beID)

	creator := appconsumer.NewCreator(repomocks.NewRepository(t), beRepo, newPolicyStub(), newAuthStub(), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:  gwID,
		Name:       "",
		Type:       domain.TypeLLM,
		BackendIDs: []uuid.UUID{beID},
	})
	if !errors.Is(err, domain.ErrInvalidName) {
		t.Fatalf("err = %v, want ErrInvalidName", err)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	gwID, beID := uuid.New(), uuid.New()
	beRepo := newBackendStub(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrAlreadyExists).Once()

	creator := appconsumer.NewCreator(repo, beRepo, newPolicyStub(), newAuthStub(), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:  gwID,
		Name:       "dupe",
		Type:       domain.TypeLLM,
		BackendIDs: []uuid.UUID{beID},
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}
