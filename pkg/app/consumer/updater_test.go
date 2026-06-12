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
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func ptr[T any](v T) *T { return &v }

func existingConsumer(gwID ids.GatewayID, beID ids.RegistryID) *domain.Consumer {
	now := time.Now().UTC()
	return domain.Rehydrate(domain.RehydrateParams{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gwID,
		Name:        "old",
		Type:        domain.TypeLLM,
		Path:        "/v1/chat",
		LLM:         &domain.LLMPolicy{Algorithm: "round-robin"},
		Active:      true,
		RegistryIDs: []ids.RegistryID{beID},
		CreatedAt:   now,
		UpdatedAt:   now,
	})
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
			return c.ID == existing.ID && c.Name == "new" && c.Type == domain.TypeMCP &&
				len(c.RegistryIDs) == 1 && c.RegistryIDs[0] == beID
		})).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("new"),
		Type:      ptr(domain.TypeMCP),
		Path:      ptr("/v1/messages"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "new" || got.Type != domain.TypeMCP {
		t.Fatalf("not applied: %+v", got)
	}
}

func TestUpdater_Update_Partial_PreservesFieldsAndAssociations(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.Name == "renamed" && c.Path == "/v1/chat" &&
				c.Algorithm() == "round-robin" && c.Type == domain.TypeLLM &&
				len(c.RegistryIDs) == 1 && c.RegistryIDs[0] == beID
		})).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Path != "/v1/chat" || got.Algorithm() != "round-robin" {
		t.Fatalf("fields not preserved: %+v", got)
	}
	if len(got.RegistryIDs) != 1 || got.RegistryIDs[0] != beID {
		t.Fatalf("associations not preserved: %+v", got.RegistryIDs)
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, mock.Anything).Return(nil, domain.ErrNotFound).Once()

	updater := appconsumer.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID: ids.New[ids.ConsumerKind](),
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestUpdater_Update_RejectsModelPolicyForUnassociatedRegistry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appconsumer.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("n"),
		Type:      ptr(domain.TypeLLM),
		Path:      ptr("/v1/chat"),
		ModelPolicies: ptr(domain.ModelPolicies{
			ids.New[ids.RegistryKind](): {},
		}),
	})
	if !errors.Is(err, registrydomain.ErrInvalidRegistryID) {
		t.Fatalf("err = %v, want ErrInvalidRegistryID", err)
	}
}

func TestUpdater_Update_AllowsModelPolicyForAssociatedRegistry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()

	updater := appconsumer.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("n"),
		Type:      ptr(domain.TypeLLM),
		Path:      ptr("/v1/chat"),
		ModelPolicies: ptr(domain.ModelPolicies{
			beID: {Allowed: []string{"gpt-4o"}, Default: "gpt-4o"},
		}),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func TestUpdater_Update_RejectsCrossGateway(t *testing.T) {
	t.Parallel()
	gwID, otherGW := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appconsumer.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: otherGW,
		Name:      ptr("n"),
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}
