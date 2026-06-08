package registry_test

import (
	"context"
	"errors"
	"testing"

	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewRegistry(ids.New[ids.GatewayKind](), "old", "openai", nil, "", 1, domain.NewAPIKeyAuth("sk-1"), nil)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.ID == existing.ID && b.Name == "new"
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:       existing.ID,
		Name:     "new",
		Provider: "openai",
		Auth:     domain.NewAPIKeyAuth("sk-1"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "new" {
		t.Fatalf("Name = %q, want %q", got.Name, "new")
	}
}

func TestUpdater_Update_PreservesRedactedSecret(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewRegistry(ids.New[ids.GatewayKind](), "old", "openai", nil, "", 1, domain.NewAPIKeyAuth("sk-real"), nil)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.Auth != nil && b.Auth.APIKey != nil && b.Auth.APIKey.APIKey == "sk-real"
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:       existing.ID,
		Name:     "old",
		Provider: "openai",
		Auth:     domain.NewAPIKeyAuth("***"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Auth.APIKey.APIKey != "sk-real" {
		t.Fatalf("api key = %q, want preserved sk-real", got.Auth.APIKey.APIKey)
	}
}

func TestUpdater_Update_PreservesSecretWhenAuthOmitted(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewRegistry(ids.New[ids.GatewayKind](), "old", "openai", nil, "", 1, domain.NewAPIKeyAuth("sk-real"), nil)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.Name == "renamed" && b.Auth != nil && b.Auth.APIKey.APIKey == "sk-real"
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:       existing.ID,
		Name:     "renamed",
		Provider: "openai",
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Auth == nil || got.Auth.APIKey.APIKey != "sk-real" {
		t.Fatalf("auth not preserved when omitted: %+v", got.Auth)
	}
}

func TestUpdater_Update_RejectsGatewayIDChange(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewRegistry(ids.New[ids.GatewayKind](), "x", "openai", nil, "", 1, domain.NewAPIKeyAuth("sk-1"), nil)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:        existing.ID,
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "x",
		Provider:  "openai",
		Auth:      domain.NewAPIKeyAuth("sk-1"),
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.RegistryKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:       id,
		Name:     "x",
		Provider: "openai",
		Auth:     domain.NewAPIKeyAuth("sk-1"),
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
