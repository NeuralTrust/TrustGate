package auth_test

import (
	"context"
	"errors"
	"testing"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func existingAuth(gwID ids.GatewayID) *domain.Auth {
	a, _ := domain.NewAuth(gwID, "current", domain.TypeAPIKey, true, validConfig())
	return a
}

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingAuth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
			return a.ID == existing.ID && a.Name == "renamed"
		})).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      "renamed",
		Type:      domain.TypeAPIKey,
		Enabled:   true,
		Config:    validConfig(),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "renamed" {
		t.Fatalf("expected renamed, got %s", got.Name)
	}
}

func TestUpdater_Update_GatewayMismatch(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingAuth(ids.New[ids.GatewayKind]())
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appauth.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "renamed",
		Type:      domain.TypeAPIKey,
		Config:    validConfig(),
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	updater := appauth.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:     id,
		Name:   "x",
		Type:   domain.TypeAPIKey,
		Config: validConfig(),
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
