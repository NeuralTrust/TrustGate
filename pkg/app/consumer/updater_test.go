package consumer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	backendmocks "github.com/NeuralTrust/AgentGateway/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func existingConsumer(gwID ids.GatewayID, beID ids.RegistryID) *domain.Consumer {
	now := time.Now().UTC()
	return domain.Rehydrate(
		ids.New[ids.ConsumerKind](), gwID, "old", domain.TypeLLM,
		"/v1/chat", "round-robin", nil,
		nil, true,
		[]ids.RegistryID{beID}, nil, nil,
		nil,
		nil,
		now, now,
	)
}

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
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
		Return([]*registrydomain.Registry{{ID: beID, GatewayID: gwID}}, nil).
		Once()

	updater := appconsumer.NewUpdater(repo, beRepo, newPolicyStub(), newAuthStub(), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:          existing.ID,
		GatewayID:   gwID,
		Name:        "new",
		Type:        domain.TypeMCP,
		Path:        "/v1/messages",
		Algorithm:   "round-robin",
		RegistryIDs: []ids.RegistryID{beID},
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
		ID:          ids.New[ids.ConsumerKind](),
		RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()},
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestUpdater_Update_RejectsCrossGatewayRegistry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	beRepo := &backendmocks.Repository{}
	beRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.Anything).
		Return([]*registrydomain.Registry{}, nil).
		Once()

	updater := appconsumer.NewUpdater(repo, beRepo, newPolicyStub(), newAuthStub(), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:          existing.ID,
		GatewayID:   gwID,
		Name:        "n",
		Type:        domain.TypeLLM,
		RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()},
	})
	if !errors.Is(err, registrydomain.ErrInvalidRegistryID) {
		t.Fatalf("err = %v, want ErrInvalidRegistryID", err)
	}
}

func TestUpdater_Update_RejectsCrossGateway(t *testing.T) {
	t.Parallel()
	gwID, otherGW := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	beRepo := &backendmocks.Repository{}
	updater := appconsumer.NewUpdater(repo, beRepo, newPolicyStub(), newAuthStub(), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:          existing.ID,
		GatewayID:   otherGW,
		Name:        "n",
		RegistryIDs: []ids.RegistryID{beID},
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}
