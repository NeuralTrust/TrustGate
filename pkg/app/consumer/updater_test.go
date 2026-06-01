package consumer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	backendmocks "github.com/NeuralTrust/AgentGateway/pkg/domain/backend/mocks"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func existingConsumer(gwID, beID uuid.UUID) *domain.Consumer {
	now := time.Now().UTC()
	return domain.Rehydrate(
		uuid.New(), gwID, "old", domain.TypeLLM,
		"/v1/chat", "round-robin", nil,
		nil, true,
		[]uuid.UUID{beID}, nil, nil,
		now, now,
	)
}

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	gwID, beID := uuid.New(), uuid.New()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.ID == existing.ID && c.Name == "new" && c.Type == domain.TypeMCP
		})).
		Return(nil).
		Once()

	beRepo := &backendmocks.Repository{}
	beRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.Anything).
		Return([]*backenddomain.Backend{{ID: beID, GatewayID: gwID}}, nil).
		Once()

	updater := appconsumer.NewUpdater(repo, beRepo, newPolicyStub(), newAuthStub(), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:         existing.ID,
		GatewayID:  gwID,
		Name:       "new",
		Type:       domain.TypeMCP,
		Path:       "/v1/messages",
		Algorithm:  "round-robin",
		BackendIDs: []uuid.UUID{beID},
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "new" || got.Type != domain.TypeMCP {
		t.Fatalf("not applied: %+v", got)
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, mock.Anything).Return(nil, domain.ErrNotFound).Once()

	beRepo := &backendmocks.Repository{}
	updater := appconsumer.NewUpdater(repo, beRepo, newPolicyStub(), newAuthStub(), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:         uuid.New(),
		BackendIDs: []uuid.UUID{uuid.New()},
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestUpdater_Update_RejectsCrossGatewayBackend(t *testing.T) {
	t.Parallel()
	gwID := uuid.New()
	beID := uuid.New()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	beRepo := &backendmocks.Repository{}
	beRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.Anything).
		Return([]*backenddomain.Backend{}, nil).
		Once()

	updater := appconsumer.NewUpdater(repo, beRepo, newPolicyStub(), newAuthStub(), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:         existing.ID,
		GatewayID:  gwID,
		Name:       "n",
		Type:       domain.TypeLLM,
		BackendIDs: []uuid.UUID{uuid.New()},
	})
	if !errors.Is(err, backenddomain.ErrInvalidBackendID) {
		t.Fatalf("err = %v, want ErrInvalidBackendID", err)
	}
}

func TestUpdater_Update_RejectsCrossGateway(t *testing.T) {
	t.Parallel()
	gwID, otherGW := uuid.New(), uuid.New()
	beID := uuid.New()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	beRepo := &backendmocks.Repository{}
	updater := appconsumer.NewUpdater(repo, beRepo, newPolicyStub(), newAuthStub(), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:         existing.ID,
		GatewayID:  otherGW,
		Name:       "n",
		BackendIDs: []uuid.UUID{beID},
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}
